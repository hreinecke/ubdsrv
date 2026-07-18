/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef INTERNAL_H_
#define INTERNAL_H_

struct sheep_aiocb {
	struct sd_request *request;
	off_t offset;
	size_t length;
	int ret;
	uint32_t nr_requests;
	char *buf;
	int buf_iter;
	const struct sd_op_template *op;
	void (*aio_done_func)(struct sheep_aiocb *);
};

struct sheep_request {
	struct list_node list;
	struct sheep_aiocb *aiocb;
	uint64_t oid;
	uint64_t cow_oid;
	uint32_t seq_num;
	uint8_t opcode;
	uint32_t offset;
	uint32_t length;
	char *buf;
};

struct sd_op_template {
	const char *name;
	int (*request_process)(struct sheep_aiocb *aiocb);
	int (*response_process)(struct sheep_request *req, struct sd_rsp *rsp);
};

static inline void sd_init_req(struct sd_req *req, uint8_t opcode)
{
	memset(req, 0, sizeof(*req));
	req->opcode = opcode;
	req->proto_ver = SD_PROTO_VER;
}

static inline const char *sd_strerror(int err)
{
	static const char *descs[256] = {
		/* from sheepdog_proto.h */
		[SD_RES_SUCCESS] = "Success",
		[SD_RES_UNKNOWN] = "Unknown error",
		[SD_RES_NO_OBJ] = "No object found",
		[SD_RES_EIO] = "I/O error",
		[SD_RES_VDI_EXIST] = "VDI exists already",
		[SD_RES_INVALID_PARMS] = "Invalid parameters",
		[SD_RES_SYSTEM_ERROR] = "System error",
		[SD_RES_VDI_LOCKED] = "VDI is already locked",
		[SD_RES_NO_VDI] = "No VDI found",
		[SD_RES_NO_BASE_VDI] = "No base VDI found",
		[SD_RES_VDI_READ] = "Failed to read from requested VDI",
		[SD_RES_VDI_WRITE] = "Failed to write to requested VDI",
		[SD_RES_BASE_VDI_READ] = "Failed to read from base VDI",
		[SD_RES_BASE_VDI_WRITE] = "Failed to write to base VDI",
		[SD_RES_NO_TAG] = "Failed to find requested tag",
		[SD_RES_STARTUP] = "System is still booting",
		[SD_RES_VDI_NOT_LOCKED] = "VDI is not locked",
		[SD_RES_SHUTDOWN] = "System is shutting down",
		[SD_RES_NO_MEM] = "Out of memory on server",
		[SD_RES_FULL_VDI] = "Maximum number of VDIs reached",
		[SD_RES_VER_MISMATCH] = "Protocol version mismatch",
		[SD_RES_NO_SPACE] = "Server has no space for new objects",
		[SD_RES_WAIT_FOR_FORMAT] = "Waiting for cluster to be formatted",
		[SD_RES_WAIT_FOR_JOIN] = "Waiting for other nodes to join cluster",
		[SD_RES_JOIN_FAILED] = "Node has failed to join cluster",
		[SD_RES_HALT] =
			"IO has halted as there are not enough living nodes",
		[SD_RES_READONLY] = "Object is read-only",
		[SD_RES_INODE_INVALIDATED] = "Inode object is invalidated",
	};

	if (!(0 <= err && err < ARRAY_SIZE(descs)) || descs[err] == NULL) {
		static __thread char msg[32];
		snprintf(msg, sizeof(msg), "Invalid error code %x", err);
		return msg;
	}

	return descs[err];
}

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

static inline size_t count_data_objs(const struct sd_inode_header *inode)
{
	return DIV_ROUND_UP(inode->vdi_size,
			    (1UL << inode->block_size_shift));
}

struct sheep_request *find_inflight_request_oid(struct sd_cluster *c,
						       uint64_t oid);
struct sheep_request *alloc_sheep_request(struct sheep_aiocb *aiocb,
						 uint64_t oid, uint64_t cow_oid,
						 int len, int offset);
int end_sheep_request(struct sheep_request *req);
int sheep_submit_sdreq(struct sd_cluster *c, struct sd_req *hdr,
			      void *data, uint32_t wlen);
int submit_sheep_request(struct sheep_request *req);

const struct sd_op_template *get_sd_op(uint8_t opcode);
void submit_blocking_sheep_request(struct sd_cluster *c, uint64_t oid);

uint32_t sheep_inode_get_vid(struct sd_request *req, uint32_t idx);

struct sd_request *alloc_request(struct sd_cluster *c, void *data,
	size_t count, enum sheep_request_type op);
void queue_request(struct sd_request *req);
void free_request(struct sd_request *req);

#endif
