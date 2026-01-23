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
#include "ublksrv_utils.h"
#include "sheepdog_proto.h"
#include "sheep.h"

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
		ublk_err( "%s: getaddrinfo failed: %s\n",
			  __func__, gai_strerror(e));
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
		ublk_err( "%s: no valid addresses found for %s:%s\n",
			  __func__, addr, port);
		sock = -1;
		goto err;
	}

	e = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(int));
err:
	freeaddrinfo(ai);
	return sock;
}

static int sheepdog_submit(int fd, struct sd_req *req, struct sd_rsp *rsp,
			   void *addr)
{
	size_t buflen = req->data_length;
	struct iovec iov[3], *sendmsg_iov = NULL, *recvmsg_iov = NULL;
	int sendmsg_iovs = 1, recvmsg_iovs = 1;
	bool is_write = req->flags & SD_FLAG_CMD_WRITE;
	struct msghdr msg;
	int ret;

	iov[0] = (struct iovec){
		.iov_base = req,
		.iov_len = sizeof(*req),
	};
	sendmsg_iov = &iov[0];
	if (addr) {
		iov[1] = (struct iovec){
			.iov_base = (void *)addr,
			.iov_len = buflen,
		};
		iov[2] = (struct iovec){
			.iov_base = rsp,
			.iov_len = sizeof(*rsp),
		};
		if (is_write) {
			recvmsg_iov = &iov[2];
			sendmsg_iovs++;
		} else {
			recvmsg_iov = &iov[1];
			recvmsg_iovs++;
		}
	} else {
		iov[1] = (struct iovec){
			.iov_base = rsp,
			.iov_len = sizeof(*rsp),
		};
		recvmsg_iov = &iov[1];
	}
	msg = (struct msghdr) {
		.msg_iov = sendmsg_iov,
		.msg_iovlen = sendmsg_iovs,
	};
	ret = sendmsg(fd, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		ublk_err("%s: sendmsg failed, errno %d\n",
			 __func__, errno);
		return -errno;
	}
	msg = (struct msghdr) {
		.msg_iov = recvmsg_iov,
		.msg_iovlen = recvmsg_iovs,
	};
	ret = recvmsg(fd, &msg, MSG_WAITALL);
	if (ret < 0) {
		ublk_err("%s: recvmsg failed, errno %d\n",
			 __func__, errno);
		return -errno;
	}
	if (rsp->result)
		ublk_err("%s: sheepdog rsp %d\n",
			 __func__, rsp->result);
	switch (rsp->result) {
	case SD_RES_SUCCESS:
		ret = 0;
		break;
	case SD_RES_NO_OBJ:
	case SD_RES_NO_VDI:
	case SD_RES_NO_BASE_VDI:
		ret = -ENOENT;
		break;
	case SD_RES_VDI_EXIST:
		ret = -EEXIST;
		break;
	case SD_RES_INVALID_PARMS:
		ret = -EINVAL;
		break;
	default:
		ret = -EIO;
		break;
	}
	return ret;
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

	ret = sheepdog_submit(fd, &req, &rsp, (void *)name);
	if (ret < 0) {
		ublk_err( "%s: failed to lookup vdi '%s', error %d\n",
			  __func__, name, ret);
		return ret;
	}

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
	ret = sheepdog_submit(fd, &req, &rsp, &inode);
	if (ret < 0) {
		ublk_err( "%s: failed to read inode from vid '%d', error %d\n",
			  __func__, vdi_id, ret);
		return ret;
	}
	p->basic.chunk_sectors = SD_DATA_OBJ_SIZE;
	p->basic.physical_bs_shift = inode.block_size_shift;
	p->basic.dev_sectors = inode.vdi_size >> 9;
	return 0;
}

int sheepdog_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, int tag)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	const struct sheepdog_tgt_data *tgt_data = q->dev->tgt.tgt_data;
	uint32_t object_size = (uint32_t)(1 << tgt_data->block_size_shift);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	uint64_t oid = vid_to_data_oid(tgt_data->vid, idx), cow_oid = 0;
	int ublk_op = ublksrv_get_op(iod);

	memset(&sd_io->req, 0, sizeof(sd_io->req));
	memset(&sd_io->rsp, 0, sizeof(sd_io->rsp));
	sd_io->req.id = tag;
	if (ublk_op == UBLK_IO_OP_WRITE) {
		sd_io->req.opcode = SD_OP_WRITE_OBJ;
		sd_io->req.obj.cow_oid = oid;
		sd_io->req.flags = SD_FLAG_CMD_WRITE;
	} else
		sd_io->req.opcode = SD_OP_READ_OBJ;
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.offset = start;
	sd_io->req.data_length = total;

	return sheepdog_submit(q_ctx->fd, &sd_io->req,
			       &sd_io->rsp, (void *)iod->addr);
}

int sheepdog_discard(const struct ublksrv_queue *q,
		     const struct ublksrv_io_desc *iod,
		     struct sd_io_context *sd_io, int tag)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	const struct sheepdog_tgt_data *tgt_data = q->dev->tgt.tgt_data;
	uint32_t object_size = (uint32_t)(1 << tgt_data->block_size_shift);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t idx = offset / object_size;
	uint64_t oid = vid_to_data_oid(tgt_data->vid, idx);

	memset(&sd_io->req, 0, sizeof(sd_io->req));
	memset(&sd_io->rsp, 0, sizeof(sd_io->rsp));
	sd_io->req.id = tag;
	sd_io->req.opcode = SD_OP_REMOVE_OBJ;
	sd_io->req.obj.oid = oid;

	return sheepdog_submit(q_ctx->fd, &sd_io->req, &sd_io->rsp, NULL);
}
