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

/* locking is done by the caller */
static inline bool is_data_obj_writable(struct sheepdog_vdi *ubd_vdi,
					uint32_t idx)
{
	bool writable;

	writable = (ubd_vdi->vid == ubd_vdi->inode.data_vdi_id[idx]);

	return writable;
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

int connect_to_sheep(const char *cluster_host, const char *cluster_port)
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

	e = getaddrinfo(cluster_host, cluster_port,
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
			  __func__, cluster_host, cluster_port);
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
	case SD_RES_VDI_LOCKED:
		ret = -EILSEQ;
		break;
	default:
		ret = -EIO;
		break;
	}
	return ret;
}

/* --- Sheepdog Protocol Handshake --- */

int sheepdog_vdi_lookup(int fd, const char *vdi_name, uint32_t snapid,
		const char *tag, uint32_t *vid, bool snapshot)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	size_t buflen = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	char name_buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN] = {0};
	int ret;

	if (snapshot)
		req.opcode = SD_OP_GET_VDI_INFO;
	else
		req.opcode = SD_OP_LOCK_VDI;
	req.proto_ver = SD_PROTO_VER;
	req.data_length = buflen;
	req.flags = SD_FLAG_CMD_WRITE;
	req.vdi.type = LOCK_TYPE_SHARED;
	req.vdi.snapid = snapid;
	memset(name_buf, 0, buflen);
	strncpy(name_buf, vdi_name, SD_MAX_VDI_LEN - 1);
	if (tag)
		strncpy(name_buf + SD_MAX_VDI_LEN, tag,
			SD_MAX_VDI_TAG_LEN - 1);

	ret = sheepdog_submit(fd, &req, &rsp, name_buf);
	if (ret < 0) {
		if (ret == -EILSEQ)
			ublk_err( "%s: vdi '%s' is locked\n",
			  __func__, name_buf);
		else
			ublk_err( "%s: failed to lookup vdi '%s', error %d\n",
				  __func__, name_buf, ret);
		return ret;
	}

	*vid = rsp.vdi.vdi_id;
	return 0;
}

int sheepdog_vdi_release(int fd, struct sheepdog_vdi *vdi)
{
	struct sd_req req = {0};
	struct sd_rsp rsp = {0};
	int ret;

	req.opcode = SD_OP_RELEASE_VDI;
	req.vdi.type = LOCK_TYPE_SHARED;
	req.vdi.base_vdi_id = vdi->vid;

	ret = sheepdog_submit(fd, &req, &rsp, NULL);
	if (ret < 0) {
		ublk_err( "%s: failed to release vdi '%x', error %d\n",
			  __func__, vdi->vid, ret);
		return ret;
	}

	return 0;
}

int sd_read_object(int fd, uint64_t oid, char *buf, size_t offset,
		size_t len, int *need_reload)
{
	struct sd_io_context *sd_io;
	struct sd_req *req;
	struct sd_rsp *rsp;
	int ret;

retry:
	sd_io = calloc(1, sizeof(struct sd_io_context));
	if (!sd_io)
		return -ENOMEM;

	req = &sd_io->req;
	rsp = &sd_io->rsp;
	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.opcode = SD_OP_READ_OBJ;
	sd_io->req.data_length = len;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.offset = offset;
	sd_io->addr = buf;
	ublk_err ( "%s: opcode %u oid %llx len %llu\n",
		   __func__, sd_io->req.opcode, sd_io->req.obj.oid,
		   sd_io->req.data_length);
	ret = sheepdog_submit(fd, &sd_io->req, &sd_io->rsp, sd_io->addr);
	if (ret < 0) {
		if (rsp->result == SD_RES_INODE_INVALIDATED) {
			ublk_err("%s: inode object is invalidated\n",
				 __func__);
			*need_reload = 2;
			ret = 0;
		} else if (sd_io->rsp.result == SD_RES_READONLY) {
			ublk_err("%s: oid %llx is read-only\n",
				 __func__, sd_io->req.obj.oid);
			*need_reload = 1;
			ret = 0;
		} else {
			if (sd_io->rsp.result == SD_RES_NO_OBJ &&
			    oid & VDI_BIT) {
				/*
				 * internal sheepdog race;
				 * VDI became snapshot but inode
				 * object has not been created (yet).
				 */
				ublk_err("%s: oid %llx not found, retry\n",
					 __func__, sd_io->req.obj.oid);
				free(sd_io);
				goto retry;
			}
			ublk_err( "%s: error reading oid %llx, rsp %u, error %d\n",
				  __func__, sd_io->req.obj.oid,
				  sd_io->rsp.result, ret);
		}
	}
	free(sd_io);
	return ret < 0 ? ret : 0;
}

static int sd_refresh_required(int fd, struct sheepdog_vdi *sd_vdi)
{
	uint32_t dummy;
	int need_reload = 0, ret;

	/* Dummy read of the inode oid */
	ret = sd_read_object(fd, vid_to_vdi_oid(sd_vdi->vid),
			     (char *)&dummy, 0, sizeof(dummy), &need_reload);
	return need_reload;
}

int sheepdog_read_inode(int fd, struct sheepdog_vdi *sd_vdi)
{
	int need_reload = 0, ret;
	struct sd_inode *inode;
	uint32_t vid = sd_vdi->vid;

	inode = calloc(1, SD_INODE_SIZE);
	if (!inode)
		return -ENOMEM;
	pthread_mutex_lock(&sd_vdi->inode_lock);
	ret = sd_read_object(fd, vid_to_vdi_oid(vid),
			     (char *)inode, 0, SD_INODE_SIZE,
			     &need_reload);
	if (ret == 0 && inode->snap_ctime) {
		/*
		 * Internal sheepdog race, resolve VID for
		 * read-onlye snapshot.
		 */
		ret = sheepdog_vdi_lookup(fd, inode->name, CURRENT_VDI_ID,
					  NULL, &vid, false);
		if (ret == 0)
			ret = sd_read_object(fd, vid_to_vdi_oid(vid),
					     (char *)inode, 0, SD_INODE_SIZE,
					     &need_reload);
	}
	if (ret == 0)
		memcpy(&sd_vdi->inode, inode, sizeof(*inode));
	pthread_mutex_unlock(&sd_vdi->inode_lock);
	free(inode);
	return ret;
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

	sd_io = calloc(1, sizeof(struct sd_io_context));
	req = &sd_io->req;
	rsp = &sd_io->rsp;
	req->proto_ver = SD_PROTO_VER;
	req->opcode = SD_OP_WRITE_OBJ;
	req->flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_TGT;
	req->data_length = sizeof(vid);
	req->obj.oid = vid_to_vdi_oid(ubd_vdi->vid);
	req->obj.cow_oid = 0;
	req->obj.offset = SD_INODE_HEADER_SIZE + sizeof(vid) * idx;
	ret = sheepdog_submit(fd, req, rsp, &vid);
	if (ret < 0) {
		ublk_err( "%s: failed to update inode oid %llx from vid '%x', error %d\n",
			  __func__, req->obj.oid, vid, ret);
		free(sd_io);
		return ret;
	}
	free(sd_io);
	return 0;
}

static int sheepdog_prep_read(int fd, struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io)
{
	uint32_t object_size = SD_DATA_OBJ_SIZE;
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	uint32_t vid = sheepdog_inode_get_idx(sd_vdi, idx);
	uint64_t oid = vid_to_data_oid(vid, idx);
	int ublk_op = ublksrv_get_op(iod);
	size_t len = object_size - start;
	int ret = 0;

	/* No object present, return NULL */
	if (!vid) {
		if (!sd_refresh_required(fd, sd_vdi)) {
			memset((void *)iod->addr, 0, total);
			return 0;
		}
		ret = sheepdog_read_inode(fd, sd_vdi);
		if (ret) {
			ublk_err("%s: failed to reload inode\n",
				 __func__);
			return ret;
		}
	}
	sd_io->type = SHEEP_READ;
	sd_io->addr = (void *)iod->addr;

	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.opcode = SD_OP_READ_OBJ;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.offset = start;
	sd_io->req.data_length = total;
	sd_io->req.obj.copies = sd_vdi->inode.nr_copies;

	ublk_err("%s: read oid %llx from vid %x\n",
		 __func__, oid, vid);

	return 1;
}

static int sheepdog_prep_discard(struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, bool write_zeroes)
{
	uint32_t object_size = SD_DATA_OBJ_SIZE;
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	uint32_t vid = sheepdog_inode_get_idx(sd_vdi, idx);
	int ublk_op = ublksrv_get_op(iod);
	size_t len = object_size - start;
	int ret = 0;

	/* No object present, return NULL */
	if (!vid) {
		if (write_zeroes)
			memset((void *)iod->addr, 0, total);
		return 0;
	}
	sd_io->type = SHEEP_DISCARD;
	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.opcode = SD_OP_WRITE_OBJ;
	sd_io->req.flags |= SD_FLAG_CMD_WRITE;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;
	pthread_mutex_lock(&sd_vdi->inode_lock);
	if (sd_vdi->inode.data_vdi_id[idx] != vid) {
		ublk_err("%s: invalid inode data index %x for vid %x\n",
			 sd_vdi->inode.data_vdi_id[idx], vid);
		vid = 0;
	} else
		sd_vdi->inode.data_vdi_id[idx] = 0;
	pthread_mutex_unlock(&sd_vdi->inode_lock);
	if (!vid)
		return -ENOENT;
	total = sizeof(vid);
	sd_io->addr = (void *)&sd_vdi->inode.data_vdi_id[idx];
	sd_io->req.obj.oid = vid_to_vdi_oid(vid);
	sd_io->req.obj.offset = SD_INODE_HEADER_SIZE + sizeof(vid) * idx;
	sd_io->req.data_length = sizeof(vid);
	sd_io->req.obj.copies = sd_vdi->inode.nr_copies;

	ublk_err("%s: discard oid %llx of vid %x\n",
			 __func__, sd_io->req.obj.oid, vid);
	return 1;
}

static int sheepdog_prep_write(struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io)
{
	uint32_t object_size = SD_DATA_OBJ_SIZE;
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	uint32_t vid;
	uint64_t oid = 0, cow_oid = 0;
	int ublk_op = ublksrv_get_op(iod);
	size_t len = object_size - start;

	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;
	sd_io->addr = (void *)iod->addr;
	/* create object if none exists */
	pthread_mutex_lock(&sd_vdi->inode_lock);
	vid = sd_vdi->inode.data_vdi_id[idx];
	if (!vid) {
		vid = sd_vdi->vid;
		oid = vid_to_data_oid(vid, idx);
		/* Update inode */
		sd_vdi->inode.data_vdi_id[idx] = vid;

		sd_io->type = SHEEP_CREATE;
		sd_io->req.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		ublk_err("%s: create new oid %llx from vid %x\n",
			 __func__, oid, vid);
	} else if (!is_data_obj_writable(sd_vdi, idx)) {
		/* use copy-on-write */
		cow_oid = vid_to_data_oid(vid, idx);
		vid = sd_vdi->vid;
		oid = vid_to_data_oid(vid, idx);
		/* Update inode */
		sd_vdi->inode.data_vdi_id[idx] = vid;

		sd_io->type = SHEEP_CREATE;
		sd_io->req.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		sd_io->req.flags |= SD_FLAG_CMD_COW;
		ublk_err("%s: create new obj %llx cow %llx from vid %x\n",
			 __func__, oid, cow_oid, vid);
	} else {
		oid = vid_to_data_oid(vid, idx);
		sd_io->type = SHEEP_WRITE;
		sd_io->req.opcode = SD_OP_WRITE_OBJ;
		ublk_err("%s: write oid %llx\n",
			 __func__, oid);
	}
	pthread_mutex_unlock(&sd_vdi->inode_lock);

	sd_io->req.obj.oid = oid;
	sd_io->req.obj.cow_oid = cow_oid;
	sd_io->req.obj.offset = start;
	sd_io->req.data_length = total;
	sd_io->req.obj.copies = sd_vdi->inode.nr_copies;

	return 1;
}

int sheepdog_rw(const struct ublksrv_queue *q,
		struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, int tag)
{
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;
	uint32_t object_size = SD_DATA_OBJ_SIZE;
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	int ublk_op = ublksrv_get_op(iod);
	size_t len = object_size - start;
	int ret = 0;

	if (total > len) {
		ublk_err("%s: op %u access beyond object size off %llu total %llu\n",
			 __func__, ublk_op, offset, total);
		ret = -EIO;
	}
	memset(&sd_io->req, 0, sizeof(sd_io->req));
	memset(&sd_io->rsp, 0, sizeof(sd_io->rsp));
	sd_io->req.id = tag;
	switch (ublk_op) {
	case UBLK_IO_OP_WRITE:
		ret = sheepdog_prep_write(sd_vdi, iod, sd_io);
		break;
	case UBLK_IO_OP_READ:
		ret = sheepdog_prep_read(q_ctx->fd, sd_vdi, iod, sd_io);
		break;
	case UBLK_IO_OP_DISCARD:
	case UBLK_IO_OP_WRITE_ZEROES:
		ret = sheepdog_prep_discard(sd_vdi, iod, sd_io,
			ublk_op == UBLK_IO_OP_DISCARD ? false : true);
		break;
	default:
		ublk_err("%s: tag %u op %u not supported\n",
			 __func__, tag, ublk_op);
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret < 1)
		return ret;

	ublk_err ( "%s: tag %u opcode %u oid %llx cow %llx off %llu len %llu\n",
		   __func__, tag, sd_io->req.opcode,
		   sd_io->req.obj.oid, sd_io->req.obj.cow_oid,
		   sd_io->req.obj.offset, sd_io->req.data_length);
submit:
	ret = sheepdog_submit(q_ctx->fd, &sd_io->req,
			      &sd_io->rsp, sd_io->addr);
	if (ret) {
		ublk_err("%s: tag %u oid %llx opcode %x rsp %d\n",
			 __func__, sd_io->req.id, sd_io->req.obj.oid,
			 sd_io->req.opcode, sd_io->rsp.result);
		return ret;
	}

	if (sd_io->type == SHEEP_CREATE)
		ret = sheepdog_update_vid(q_ctx->fd, sd_vdi,
					  sd_io->req.obj.oid);
	return ret;
}
