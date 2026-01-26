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
#include <pthread.h>

#include <linux/ioctl.h>

#include "ublksrv.h"
#include "ublksrv_utils.h"
#include "sheepdog_proto.h"
#include "sheep.h"

static uint32_t sheepdog_inode_get_idx(struct sheepdog_vdi *ubd_vdi,
				       uint32_t idx)
{
	uint32_t vid;

	pthread_mutex_lock(&ubd_vdi->inode_lock);
	vid = ubd_vdi->inode.data_vdi_id[idx];
	pthread_mutex_unlock(&ubd_vdi->inode_lock);

	return vid;
}

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

int connect_to_sheep(struct sheepdog_vdi *ubd_vdi)
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

	e = getaddrinfo(ubd_vdi->cluster_host, ubd_vdi->cluster_port,
			&hints, &ai);

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
			  __func__, ubd_vdi->cluster_host,
			  ubd_vdi->cluster_port);
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
	struct iovec iov[2];
	bool is_write = req->flags & SD_FLAG_CMD_WRITE;
	struct msghdr msg;
	size_t wlen, rlen;
	int ret;

	if (is_write) {
		wlen = req->data_length;
		rlen = 0;
	} else {
		wlen = 0;
		rlen = req->data_length;
	}
	iov[0] = (struct iovec){
		.iov_base = req,
		.iov_len = sizeof(*req),
	};
	if (wlen) {
		iov[1] = (struct iovec){
			.iov_base = (void *)addr,
			.iov_len = wlen,
		};
	}
	msg = (struct msghdr) {
		.msg_iov = &iov[0],
		.msg_iovlen = wlen ? 2 : 1,
	};
	ret = sendmsg(fd, &msg, MSG_DONTWAIT);
	if (ret < 0) {
		ublk_err("%s: sendmsg req failed, errno %d\n",
			 __func__, errno);
		return -errno;
	}
	iov[0] = (struct iovec){
		.iov_base = rsp,
		.iov_len = sizeof(*rsp),
	};
	msg = (struct msghdr) {
		.msg_iov = &iov[0],
		.msg_iovlen = 1,
	};
	ret = recvmsg(fd, &msg, MSG_WAITALL);
	if (ret < 0) {
		ublk_err("%s: recvmsg rsp failed, errno %d\n",
			 __func__, errno);
		return -errno;
	}
	if (rlen > rsp->data_length)
		rlen = rsp->data_length;
	if (rlen) {
		iov[0] = (struct iovec){
			.iov_base = (void *)addr,
			.iov_len = rlen,
		};
		msg = (struct msghdr) {
			.msg_iov = &iov[0],
			.msg_iovlen = 1,
		};
		ret = recvmsg(fd, &msg, MSG_WAITALL);
		if (ret < 0) {
			ublk_err("%s: recvmsg data failed, errno %d\n",
				 __func__, errno);
			return -errno;
		}
	}

	if (rsp->result)
		ublk_err("%s: sheepdog opcode %x rsp %d\n",
			 __func__, req->opcode, rsp->result);
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

int sheepdog_vdi_lookup(int fd, struct sheepdog_vdi *vdi)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	size_t buflen = SD_MAX_VDI_LEN;
	char name_buf[SD_MAX_VDI_LEN] = {0};
	int ret;

	req.opcode = SD_OP_LOCK_VDI;
	req.data_length = buflen;
	req.flags = SD_FLAG_CMD_WRITE;

	ret = sheepdog_submit(fd, &req, &rsp, vdi->vdi_name);
	if (ret < 0) {
		ublk_err( "%s: failed to lookup vdi '%s', error %d\n",
			  __func__, vdi->vdi_name, ret);
		return ret;
	}

	vdi->vid = rsp.vdi.vdi_id;
	return 0;
}

int sheepdog_vdi_release(int fd, struct sheepdog_vdi *vdi)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	int ret;

	req.opcode = SD_OP_RELEASE_VDI;
	req.vdi.type = LOCK_TYPE_NORMAL;
	req.vdi.base_vdi_id = vdi->vid;

	ret = sheepdog_submit(fd, &req, &rsp, vdi->vdi_name);
	if (ret < 0) {
		ublk_err( "%s: failed to lookup vdi '%s', error %d\n",
			  __func__, vdi->vdi_name, ret);
		return ret;
	}

	vdi->vid = rsp.vdi.vdi_id;
	return 0;
}

int sheepdog_read_inode(int fd, struct sheepdog_vdi *vdi)
{
	struct sd_io_context *sd_io;
	struct sd_inode *inode;
	struct sd_req *req;
	struct sd_rsp *rsp;
	int ret;

	sd_io = calloc(1, sizeof(struct sd_io_context));
	inode = calloc(1, sizeof(struct sd_inode));
	req = &sd_io->req;
	rsp = &sd_io->rsp;
	req->opcode = SD_OP_READ_OBJ;
	req->data_length = SD_INODE_SIZE;
	req->obj.oid = vid_to_vdi_oid(vdi->vid);
	req->obj.offset = 0;
	ret = sheepdog_submit(fd, req, rsp, inode);
	if (ret < 0) {
		ublk_err( "%s: failed to read inode from vid '%d', error %d\n",
			  __func__, vdi->vid, ret);
		free(sd_io);
		return ret;
	}
	pthread_mutex_lock(&vdi->inode_lock);
	memcpy(&vdi->inode, inode, sizeof(*inode));
	pthread_mutex_unlock(&vdi->inode_lock);
	free(inode);
	free(sd_io);
	return 0;
}

int sheepdog_update_vid(int fd, struct sheepdog_vdi *ubd_vdi,
			uint64_t req_oid)
{
	struct sd_io_context *sd_io;
	struct sd_req *req;
	struct sd_rsp *rsp;
	uint32_t vid = ubd_vdi->vid, idx;
	uint64_t oid;
	int ret;

	oid = vid_to_vdi_oid(vid);
	idx = data_oid_to_idx(req_oid);

	pthread_mutex_lock(&ubd_vdi->inode_lock);
	ubd_vdi->inode.data_vdi_id[idx] = vid;
	pthread_mutex_unlock(&ubd_vdi->inode_lock);

	sd_io = calloc(1, sizeof(struct sd_io_context));
	req = &sd_io->req;
	rsp = &sd_io->rsp;
	req->opcode = SD_OP_WRITE_OBJ;
	req->flags = SD_FLAG_CMD_WRITE;
	req->data_length = sizeof(vid);
	req->obj.oid = vid_to_vdi_oid(ubd_vdi->vid);
	req->obj.cow_oid = 0;
	req->obj.offset = SD_INODE_HEADER_SIZE + sizeof(vid) * idx;
	ret = sheepdog_submit(fd, req, rsp, &vid);
	if (ret < 0) {
		ublk_err( "%s: failed to update inode from vid '%d', error %d\n",
			  __func__, ubd_vdi->vid, ret);
		free(sd_io);
		return ret;
	}
	free(sd_io);
	return 0;
}

int sheepdog_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, int tag)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	struct sheepdog_vdi *ubd_vdi = q->dev->tgt.tgt_data;
	uint32_t object_size =
		(uint32_t)(1 << ubd_vdi->inode.block_size_shift);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % SD_DATA_OBJ_SIZE;
	uint32_t idx = offset / SD_DATA_OBJ_SIZE;
	uint64_t oid = vid_to_data_oid(ubd_vdi->vid, idx), cow_oid = 0;
	uint32_t vid = sheepdog_inode_get_idx(ubd_vdi, idx);
	int ublk_op = ublksrv_get_op(iod);
	size_t len = SD_DATA_OBJ_SIZE - start;
	int ret = 0;

	if (total > len) {
		ublk_err("%s: access beyond object size\n", __func__);
		ret = -EIO;
	}
	memset(&sd_io->req, 0, sizeof(sd_io->req));
	memset(&sd_io->rsp, 0, sizeof(sd_io->rsp));
	sd_io->req.id = tag;
	if (ublk_op == UBLK_IO_OP_WRITE) {
		sd_io->req.opcode = SD_OP_WRITE_OBJ;
		sd_io->req.flags = SD_FLAG_CMD_WRITE;
	} else
		sd_io->req.opcode = SD_OP_READ_OBJ;
	if (vid && vid != ubd_vdi->vid) {
		if (ublk_op == UBLK_IO_OP_WRITE)
			cow_oid = vid_to_data_oid(vid, idx);
		else
			oid = vid_to_data_oid(vid, idx);
	}
	ublk_err ( "%s: off %llu, len %llu, vid %u oid %llx cow %llx idx %u\n",
		   __func__, offset, total, vid, oid, cow_oid, idx );
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.cow_oid = cow_oid;
	sd_io->req.obj.offset = start;
	sd_io->req.data_length = total;

	if (vid && !cow_oid)
		goto submit;
	switch (sd_io->type) {
	case SHEEP_WRITE:
		sd_io->req.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		if (cow_oid)
			sd_io->req.flags |= SD_FLAG_CMD_COW;
		break;
	case SHEEP_READ:
		return 0;
	}
submit:
	ret = sheepdog_submit(q_ctx->fd, &sd_io->req,
			      &sd_io->rsp, (void *)iod->addr);
	if (ret)
		return ret;

	if (sd_io->req.opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		sheepdog_update_vid(q_ctx->fd, ubd_vdi, oid);

	return ret;
}

int sheepdog_discard(const struct ublksrv_queue *q,
		     const struct ublksrv_io_desc *iod,
		     struct sd_io_context *sd_io, int tag)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	const struct sheepdog_vdi *vdi = q->dev->tgt.tgt_data;
	uint32_t object_size =
		(uint32_t)(1 << vdi->inode.block_size_shift);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t idx = offset / object_size;
	uint64_t oid = vid_to_data_oid(vdi->vid, idx);

	memset(&sd_io->req, 0, sizeof(sd_io->req));
	memset(&sd_io->rsp, 0, sizeof(sd_io->rsp));
	sd_io->req.id = tag;
	sd_io->req.opcode = SD_OP_REMOVE_OBJ;
	sd_io->req.obj.oid = oid;

	return sheepdog_submit(q_ctx->fd, &sd_io->req, &sd_io->rsp, NULL);
}
