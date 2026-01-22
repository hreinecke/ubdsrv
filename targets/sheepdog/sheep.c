#include <config.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include <linux/ioctl.h>

#include "ublksrv.h"
#include "sheepdog_proto.h"
#include "sheep.h"

enum sd_req_state {
	SD_STATE_INIT,
	SD_STATE_SEND_REQ,
	SD_STATE_SEND_DATA,
	SD_STATE_WRITE_REQ,
};

struct sd_io_context {
	int ublk_tag;
	struct sd_req req;
	struct sd_rsp rsp;
	struct iovec iov[2];
	void *addr;
	enum sd_req_state state;
};

int sheepdog_allocate_context(struct sheepdog_queue_ctx *ctx, int num_ctx)
{
	ctx->ctxs = (struct sd_io_context *)
		calloc(num_ctx, sizeof(struct sd_io_context));
	if (!ctx->ctxs)
		return -ENOMEM;
	ctx->num_ctx = num_ctx;
}

void sheepdog_free_context(struct sheepdog_queue_ctx *ctx)
{
	free(ctx->ctxs);
	ctx->ctxs = NULL;
	ctx->num_ctx = 0;
}

int connect_to_sheep(const char *addr, const char *port)
{
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	int e;

	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(addr, port, &hints, &ai);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		freeaddrinfo(ai);
		return -1;
	}

	for(rp = ai; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(sock == -1)
			continue;	/* error */

		if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;		/* success */
			
		close(sock);
	}

	if (rp == NULL) {
		sock = -1;
		goto err;
	}

	e = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(int));
err:
	freeaddrinfo(ai);
	return sock;
}

static int sheepdog_submit(int fd, struct sd_req *req, const void *buf,
			   struct sd_rsp *rsp)
{
	size_t buflen = req->data_length;
	int ret;

	ret = write(fd, req, sizeof(*req));
	if (ret != sizeof(req))
		return -EIO;
	if (buf) {
		ret = write(fd, buf, buflen);
		if (ret != buflen)
			return -EIO;
	}
	ret = read(fd, rsp, sizeof(*rsp));
	if (ret != sizeof(*rsp))
		return -EIO;

	return 0;
}

/* --- Sheepdog Protocol Handshake --- */

int sheepdog_vdi_lookup(int fd, const char *name, uint32_t *vid)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	size_t buflen = SD_MAX_VDI_LEN;
	char name_buf[SD_MAX_VDI_LEN] = {0};
	int ret;

	req.opcode = SD_OP_GET_VDI_INFO;
	req.data_length = buflen;
	req.flags = SD_FLAG_CMD_WRITE;
	strncpy(name_buf, name, strlen(name));

	ret = sheepdog_submit(fd, &req, name, &rsp);
	if (ret < 0)
		return ret;
	if (rsp.result != SD_RES_SUCCESS)
		return -ENOENT;

	*vid = rsp.vdi.vdi_id;
	return 0;
}

int sheepdog_read_params(int fd, uint32_t vdi_id, struct ublk_params *p)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	struct sd_inode inode = { 0 };
	int ret;

	req.opcode = SD_OP_READ_OBJ;
	req.data_length = SD_INODE_SIZE;
	req.obj.oid = vid_to_vdi_oid(vdi_id);
	req.obj.offset = 0;
	ret = sheepdog_submit(fd, &req, &inode, &rsp);
	if (ret < 0)
		return ret;
	if (rsp.result != SD_RES_SUCCESS)
		return -ENOENT;
	p->basic.chunk_sectors = SD_DATA_OBJ_SIZE;
	p->basic.physical_bs_shift = inode.block_size_shift;
	p->basic.dev_sectors = inode.vdi_size >> 9;
	return rsp.result != SD_RES_SUCCESS ? -ENOENT : 0;
}

int sheepdog_rw(const struct ublksrv_queue *q,
		struct io_uring_sqe *sqe,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *tgt_data)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	struct sd_io_context *sd_io = &q_ctx->ctxs[tag];
	uint32_t object_size = (uint32_t)(1 << tgt_data->block_size_shift);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	uint64_t oid = vid_to_data_oid(tgt_data->vid, idx), cow_oid = 0;
	int ublk_op = ublksrv_get_op(iod);

	sd_io->ublk_tag = tag;
	sd_io->state = SD_STATE_SEND_REQ;

	memset(&sd_io->req, 0, sizeof(sd_io->req));
	sd_io->req.id = tag;
	if (ublk_op == UBLK_IO_OP_WRITE) {
		sd_io->req.opcode = SD_OP_WRITE_OBJ;
		sd_io->req.obj.cow_oid = oid;
	} else
		sd_io->req.opcode = SD_OP_READ_OBJ;
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.offset = (uint32_t)offset;
	sd_io->req.data_length = total;
	sd_io->req.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;

	sd_io->iov[0] = (struct iovec){
		.iov_base = &sd_io->req,
		.iov_len = sizeof(sd_io->req)
	};
	if (ublksrv_get_op(iod) == UBLK_IO_OP_WRITE) {
		sd_io->iov[1] = (struct iovec){
			.iov_base = (void *)iod->addr,
			.iov_len = total,
		};
		io_uring_prep_writev(sqe, q_ctx->fd, sd_io->iov, 2, 0);
	} else {
		io_uring_prep_writev(sqe, q_ctx->fd, sd_io->iov, 1, 0);
	}
	io_uring_sqe_set_data(sqe, sd_io);
	return 1;
}

int sheepdog_discard(const struct ublksrv_queue *q,
		     struct io_uring_sqe *sqe,
		     const struct ublksrv_io_desc *iod, int tag,
		     const struct sheepdog_tgt_data *tgt_data)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	struct sd_io_context *sd_io = &q_ctx->ctxs[tag];
	uint32_t object_size = (uint32_t)(1 << tgt_data->block_size_shift);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	uint64_t oid = vid_to_data_oid(tgt_data->vid, idx);

	sd_io->ublk_tag = tag;
	sd_io->state = SD_STATE_SEND_REQ;

	memset(&sd_io->req, 0, sizeof(sd_io->req));
	sd_io->req.id = tag;
	sd_io->req.opcode = SD_OP_REMOVE_OBJ;
	sd_io->req.obj.oid = oid;

	sd_io->iov[0] = (struct iovec){
		.iov_base = &sd_io->req,
		.iov_len = sizeof(sd_io->req)
	};
	io_uring_prep_writev(sqe, q_ctx->fd, sd_io->iov, 1, 0);
	io_uring_sqe_set_data(sqe, sd_io);
	return 1;
}
