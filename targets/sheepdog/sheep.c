// SPDX-License-Identifier: GPL-2.0-only
/*
 * sheep.c - Interface functions for sheepdog
 *
 * Copyright (c) 2026 Hannes Reinecke, SUSE
 */
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

static uint32_t sd_inode_get_vid(struct sheepdog_vdi *sd_vdi,
				       uint32_t idx)
{
	uint32_t vid;

	pthread_mutex_lock(&sd_vdi->inode_lock);
	vid = sd_vdi->inode.data_vdi_id[idx];
	pthread_mutex_unlock(&sd_vdi->inode_lock);

	return vid;
}

static void sd_inode_invalidate(struct sheepdog_vdi *sd_vdi,
				bool invalidated)
{
	pthread_mutex_lock(&sd_vdi->inode_lock);
	sd_vdi->invalidated = invalidated;
	pthread_mutex_unlock(&sd_vdi->inode_lock);
}

static void sd_inode_is_snapshot(struct sheepdog_vdi *sd_vdi,
				 bool snapshot)
{
	pthread_mutex_lock(&sd_vdi->inode_lock);
	sd_vdi->is_snapshot = snapshot;
	pthread_mutex_unlock(&sd_vdi->inode_lock);
}

static void sd_inode_evaluate_result(struct sheepdog_vdi *sd_vdi,
				     struct sd_io_context *sd_io)
{
	if (sd_io->rsp.result == SD_RES_INODE_INVALIDATED)
		sd_inode_invalidate(sd_vdi, true);
	else if (sd_io->rsp.result == SD_RES_READONLY)
		sd_inode_is_snapshot(sd_vdi, true);
}

bool sd_inode_needs_reload(struct sheepdog_vdi *sd_vdi)
{
	bool needs_reload;

	pthread_mutex_lock(&sd_vdi->inode_lock);
	needs_reload = sd_vdi->invalidated || sd_vdi->is_snapshot;
	pthread_mutex_unlock(&sd_vdi->inode_lock);
	return needs_reload;
}

/* locking is done by the caller */
static inline bool is_data_obj_writable(struct sheepdog_vdi *sd_vdi,
					uint32_t idx)
{
	bool writable;

	writable = (sd_vdi->vid == sd_vdi->inode.data_vdi_id[idx]);

	return writable;
}

static int set_sock_timeout(int fd, unsigned int snd_tmo, unsigned int rcv_tmo)
{
	struct timeval timeout = {
		.tv_sec = snd_tmo,
		.tv_usec = 0,
	};
	int ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
			 (char *)&timeout, sizeof(timeout));
	if (ret < 0)
		return ret;

	timeout.tv_sec = rcv_tmo;

	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
			  (char *)&timeout, sizeof(timeout));
}

int sd_connect(const char *cluster_host, const char *cluster_port,
	       unsigned int send_tmo, unsigned int recv_tmo)
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
		return -ENETUNREACH;
	}

	for(rp = ai; rp != NULL; rp = rp->ai_next) {
		int ret;

		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (sock < 0)
			continue;	/* error */

		ret = set_sock_timeout(sock, send_tmo, recv_tmo);
		if (ret < 0) {
			ublk_err( "%s: failed to set socket timeout",
				  __func__);
			close(sock);
			ret = -errno;
			rp = NULL;
			break;
		}
		if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;		/* success */

		close(sock);
	}

	if (rp == NULL) {
		ublk_err( "%s: no valid addresses found for %s:%s\n",
			  __func__, cluster_host, cluster_port);
		sock = -EHOSTUNREACH;
		goto err;
	}

	e = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &e, sizeof(int));
err:
	freeaddrinfo(ai);
	return sock;
}

static int sd_result_to_errno(struct sd_io_context *sd_io)
{
	switch (sd_io->rsp.result) {
	case SD_RES_SUCCESS:
		return 0;
	case SD_RES_NO_OBJ:
	case SD_RES_NO_VDI:
	case SD_RES_NO_BASE_VDI:
		return -ENOENT;
	case SD_RES_VDI_EXIST:
		return -EEXIST;
	case SD_RES_INVALID_PARMS:
		return -EINVAL;
		break;
	case SD_RES_VDI_LOCKED:
		return -EILSEQ;
	default:
		break;
	}
	return -EIO;
}

static int sd_submit(int fd, struct sd_io_context *sd_io)
{
	struct iovec iov[2];
	bool is_write = sd_io->req.flags & SD_FLAG_CMD_WRITE;
	struct msghdr msg;
	size_t wlen, rlen;
	int ret;

	if (is_write) {
		wlen = sd_io->req.data_length;
		rlen = 0;
	} else {
		wlen = 0;
		rlen = sd_io->req.data_length;
	}
	iov[0] = (struct iovec){
		.iov_base = &sd_io->req,
		.iov_len = sizeof(struct sd_req),
	};
	if (wlen) {
		iov[1] = (struct iovec){
			.iov_base = (void *)sd_io->addr,
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
		.iov_base = &sd_io->rsp,
		.iov_len = sizeof(struct sd_rsp),
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
	if (rlen > sd_io->rsp.data_length)
		rlen = sd_io->rsp.data_length;
	if (rlen) {
		iov[0] = (struct iovec){
			.iov_base = (void *)sd_io->addr,
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

	return sd_result_to_errno(sd_io);
}

/* --- Sheepdog Protocol Handshake --- */

int sd_vdi_lookup(int fd, const char *vdi_name, uint32_t snapid,
		const char *tag, uint32_t *vid, bool lock)
{
	struct sd_io_context sd_io = { 0 };
	size_t buflen = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	char name_buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN] = {0};
	int ret;

	if (lock) {
		sd_io.req.opcode = SD_OP_LOCK_VDI;
		sd_io.req.vdi.type = LOCK_TYPE_SHARED;
	} else {
		sd_io.req.opcode = SD_OP_GET_VDI_INFO;
	}
	sd_io.req.proto_ver = SD_PROTO_VER;
	sd_io.req.data_length = buflen;
	sd_io.req.flags = SD_FLAG_CMD_WRITE;
	sd_io.req.vdi.snapid = snapid;
	memset(name_buf, 0, buflen);
	strncpy(name_buf, vdi_name, SD_MAX_VDI_LEN - 1);
	if (tag)
		strncpy(name_buf + SD_MAX_VDI_LEN, tag,
			SD_MAX_VDI_TAG_LEN - 1);
	sd_io.addr = name_buf;
	ret = sd_submit(fd, &sd_io);
	if (ret < 0) {
		if (ret == -EILSEQ)
			ublk_err( "%s: vdi '%s' is locked\n",
			  __func__, name_buf);
		else
			ublk_err( "%s: failed to lookup vdi '%s', result %d\n",
				  __func__, name_buf, sd_io.rsp.result);
		return ret;
	}

	*vid = sd_io.rsp.vdi.vdi_id;
	return 0;
}

int sd_vdi_release(int fd, struct sheepdog_vdi *vdi)
{
	struct sd_io_context sd_io = { 0 };
	int ret;

	sd_io.req.opcode = SD_OP_RELEASE_VDI;
	sd_io.req.vdi.type = LOCK_TYPE_SHARED;
	sd_io.req.vdi.base_vdi_id = vdi->vid;

	ret = sd_submit(fd, &sd_io);
	if (ret < 0) {
		ublk_err( "%s: failed to release vdi '%x', result %d\n",
			  __func__, vdi->vid, sd_io.rsp.result);
		return ret;
	}

	return 0;
}

int sd_read_object(int fd, struct sd_io_context *sd_io,
		uint64_t oid, void *buf, size_t offset, size_t len)
{
	int ret;

retry:
	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.opcode = SD_OP_READ_OBJ;
	sd_io->req.data_length = len;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.offset = offset;
	sd_io->addr = buf;
	ublk_err ( "%s: opcode %u oid %lx len %u\n",
		   __func__, sd_io->req.opcode, sd_io->req.obj.oid,
		   sd_io->req.data_length);
	ret = sd_submit(fd, sd_io);
	if (sd_io->rsp.result == SD_RES_NO_OBJ && (oid & VDI_BIT)) {
		/*
		 * internal sheepdog race;
		 * VDI became snapshot but inode
		 * object has not been created (yet).
		 */
		ublk_err("%s: oid %lx not found, retry\n",
			 __func__, sd_io->req.obj.oid);
		memset(sd_io, 0, sizeof(*sd_io));
		goto retry;
	} else if (ret < 0 || sd_io->rsp.result) {
		ublk_err( "%s: error reading oid %lx, rsp %u, error %d\n",
			  __func__, sd_io->req.obj.oid,
			  sd_io->rsp.result, ret);
	}
	return ret < 0 ? ret : 0;
}

int sd_read_inode(int fd, struct sheepdog_vdi *sd_vdi)
{
	struct sd_io_context sd_io = { 0 };
	int need_reload = 0, ret;
	struct sd_inode *inode;
	uint32_t vid = sd_vdi->vid;
	bool snapshot, invalidated;

	inode = calloc(1, SD_INODE_SIZE);
	if (!inode)
		return -ENOMEM;

	pthread_mutex_lock(&sd_vdi->inode_lock);
	snapshot = sd_vdi->is_snapshot;
	sd_vdi->is_snapshot = false;
	invalidated = sd_vdi->invalidated;
	sd_vdi->invalidated = false;
	pthread_mutex_unlock(&sd_vdi->inode_lock);
retry:
	if (snapshot) {
		ret = sd_vdi_lookup(fd, sd_vdi->inode.name,
				    CURRENT_VDI_ID, NULL, &vid, true);
		if (ret == 0) {
			ret = sd_read_object(fd, &sd_io, vid_to_vdi_oid(vid),
					     (char *)inode, 0,
					     SD_INODE_HEADER_SIZE);
			invalidated =
				(sd_io.rsp.result == SD_RES_INODE_INVALIDATED);
			snapshot = (sd_io.rsp.result == SD_RES_READONLY);
		}
	} else {
		ret = sd_read_object(fd, &sd_io, vid_to_vdi_oid(vid),
				     (char *)inode, 0, SD_INODE_SIZE);
		invalidated = (sd_io.rsp.result == SD_RES_INODE_INVALIDATED);
		snapshot = (sd_io.rsp.result == SD_RES_READONLY);
		if (ret == 0 && inode->snap_ctime) {
			/*
			 * Internal sheepdog race, resolve VID for
			 * read-only snapshot.
			 */
			snapshot = true;
		}
	}
	if (snapshot || invalidated)
		goto retry;
	pthread_mutex_lock(&sd_vdi->inode_lock);
	if (ret == 0)
		memcpy(&sd_vdi->inode, inode, SD_INODE_SIZE);
	else
		ublk_err("%s: failed to update inode, error %d\n",
			 __func__, ret);
	pthread_mutex_unlock(&sd_vdi->inode_lock);
	free(inode);
	return ret;
}

int sd_update_inode(int fd, struct sheepdog_vdi *sd_vdi,
		    uint64_t req_oid)
{
	struct sd_io_context sd_io = { 0 };
	uint32_t vid, idx;
	int need_reload = 0, ret;

	vid = sd_vdi->vid;
	idx = data_oid_to_idx(req_oid);

	sd_io.req.proto_ver = SD_PROTO_VER;
	sd_io.req.opcode = SD_OP_WRITE_OBJ;
	sd_io.req.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_TGT;
	sd_io.req.data_length = sizeof(vid);
	sd_io.req.obj.oid = vid_to_vdi_oid(sd_vdi->vid);
	sd_io.req.obj.offset = SD_INODE_HEADER_SIZE + sizeof(vid) * idx;
	sd_io.addr = &vid;
	ret = sd_submit(fd, &sd_io);
	sd_inode_evaluate_result(sd_vdi, &sd_io);
	if (ret < 0) {
		ublk_err( "%s: update inode oid %lx failed, rsp %d err %d\n",
			  __func__, sd_io.req.obj.oid,
			  sd_io.rsp.result, ret);
	}
	return ret;
}

int sd_update_vid(int fd, struct sheepdog_vdi *sd_vdi, uint32_t idx)
{
	int ret;

	ret = sd_read_inode(fd, sd_vdi);
	if (ret < 0)
		return ret;
	return sd_inode_get_vid(sd_vdi, idx);
}

int sd_resolve_vid(int fd, struct sheepdog_vdi *sd_vdi, uint32_t idx)
{
	uint32_t vid;
	int ret;

	vid = sd_inode_get_vid(sd_vdi, idx);
	/* Return if object is present */
	if (vid)
		return vid;

	return sd_update_vid(fd, sd_vdi, idx);
}

int sd_exec_discard(int fd, struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, uint64_t oid)
{
	uint32_t object_size = SD_OBJECT_SIZE(sd_vdi);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t idx = offset / object_size;
	uint32_t new_vid = 0;
	bool cleared = false;
	int ret = 0;

	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.opcode = SD_OP_WRITE_OBJ;
	sd_io->req.flags |= SD_FLAG_CMD_WRITE;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;

	pthread_mutex_lock(&sd_vdi->inode_lock);
	if (!sd_vdi->inode.data_vdi_id[idx])
		cleared = true;
	sd_vdi->inode.data_vdi_id[idx] = new_vid;
	pthread_mutex_unlock(&sd_vdi->inode_lock);

	if (cleared)
		return 0;
	sd_io->addr = (void *)&new_vid;
	sd_io->req.obj.oid = oid;
	sd_io->req.obj.offset = SD_INODE_HEADER_SIZE + sizeof(new_vid) * idx;
	sd_io->req.data_length = sizeof(new_vid);
	sd_io->req.obj.copies = sd_vdi->inode.nr_copies;

	ublk_err("%s: discard oid %lx\n",
			 __func__, sd_io->req.obj.oid);
	ret = sd_submit(fd, sd_io);
	sd_inode_evaluate_result(sd_vdi, sd_io);
	if (ret < 0) {
		/* Something happened during I/O, re-read inode */
		sd_inode_invalidate(sd_vdi, true);
		ublk_err("%s: tag %u oid %lx opcode %x rsp %d\n",
			 __func__, sd_io->req.id, sd_io->req.obj.oid,
			 sd_io->req.opcode, sd_io->rsp.result);
	}
	return ret;
}

static void sd_prep_write(struct sheepdog_vdi *sd_vdi,
			  struct sd_io_context *sd_io,
			  unsigned int idx, uint32_t vid)
{
	sd_io->req.proto_ver = SD_PROTO_VER;
	sd_io->req.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;
	sd_io->req.flags |= SD_FLAG_CMD_TGT;

	if (!vid) {
		/* Create new object */
		vid = sd_vdi->vid;
		sd_io->req.obj.oid = vid_to_data_oid(vid, idx);
		sd_io->req.obj.cow_oid = 0;
		/* Update inode */
		pthread_mutex_lock(&sd_vdi->inode_lock);
		sd_vdi->inode.data_vdi_id[idx] = vid;
		pthread_mutex_unlock(&sd_vdi->inode_lock);

		sd_io->req.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		ublk_err("%s: create new oid %lx from vid %x\n",
			 __func__, sd_io->req.obj.oid, vid);
	} else if (!is_data_obj_writable(sd_vdi, idx)) {
		/* use copy-on-write */
		sd_io->req.obj.cow_oid = vid_to_data_oid(vid, idx);
		vid = sd_vdi->vid;
		sd_io->req.obj.oid = vid_to_data_oid(vid, idx);
		/* Update inode */
		pthread_mutex_lock(&sd_vdi->inode_lock);
		sd_vdi->inode.data_vdi_id[idx] = vid;
		pthread_mutex_unlock(&sd_vdi->inode_lock);

		sd_io->req.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		sd_io->req.flags |= SD_FLAG_CMD_COW;
		ublk_err("%s: create new obj %lx cow %lx from vid %x\n",
			 __func__, sd_io->req.obj.oid,
			 sd_io->req.obj.cow_oid, vid);
	} else {
		sd_io->req.obj.oid = vid_to_data_oid(vid, idx);
		sd_io->req.obj.cow_oid = 0;
		sd_io->req.opcode = SD_OP_WRITE_OBJ;
		ublk_err("%s: write oid %lx\n",
			 __func__, sd_io->req.obj.oid);
	}

}
int sd_exec_write(int fd, struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, uint32_t vid)
{
	uint32_t object_size = SD_OBJECT_SIZE(sd_vdi);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	uint32_t idx = offset / object_size;
	int ret;

	memset(sd_io, 0, sizeof(*sd_io));
	sd_prep_write(sd_vdi, sd_io, idx, vid);

	sd_io->addr = (void *)iod->addr;
	sd_io->req.obj.offset = start;
	sd_io->req.data_length = total;
	sd_io->req.obj.copies = sd_vdi->inode.nr_copies;

	ret = sd_submit(fd, sd_io);
	sd_inode_evaluate_result(sd_vdi, sd_io);
	if (ret < 0) {
		ublk_err("%s: tag %u oid %lx opcode %x rsp %d\n",
			 __func__, sd_io->req.id, sd_io->req.obj.oid,
			 sd_io->req.opcode, sd_io->rsp.result);
	}
	return ret;
}
