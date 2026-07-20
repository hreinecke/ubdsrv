// SPDX-License-Identifier: GPL-2.0
/*
 * sheep.h - Definitions for sheepdog device server
 *
 * Copyright (c) 2026 Hannes Reinecke, SUSE
 */
#ifndef __SHEEP_H__
#define __SHEEP_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SD_SEND_TMO 5
#define SD_RECV_TMO 60

struct sd_vdi {
	char vdi_name[256];
	uint32_t vid;
	pthread_mutex_t inode_lock;
	struct sd_inode inode;
	bool invalidated;
	bool is_snapshot;
};

struct sd_queue_ctx {
	int fd;
	unsigned long timeout;
};

enum sheep_request_type {
	VDI_READ = 1,
	VDI_WRITE,
	VDI_CREATE,
	SHEEP_CTL,
};

struct sd_request {
	struct sd_req req;
	struct sd_rsp rsp;
	uint32_t vid;
	void *addr;
	size_t length;
	off_t offset;
	enum sheep_request_type opcode;
	int ret;
};

#define SD_OBJECT_SIZE(v) (UINT32_C(1) << (v)->inode.block_size_shift)

 int sd_connect(const char *cluster_host, const char *cluster_port,
		unsigned int send_tmo, unsigned int recv_tmo);
int sd_vdi_lookup(struct sd_queue_ctx *ctx, const char *vdi_name,
		uint32_t snapid, const char *tag, uint32_t *vid, bool lock);
int sd_vdi_release(struct sd_queue_ctx *ctx, struct sd_vdi *vdi);
bool sd_inode_needs_reload(struct sd_vdi *sd_vdi);
int sd_read_object(struct sd_queue_ctx *ctx, struct sd_request *sd_io,
		   uint64_t oid);
int sd_read_inode(struct sd_queue_ctx *ctx, struct sd_vdi *vdi);
int sd_update_inode(struct sd_queue_ctx *ctx, struct sd_vdi *sd_vdi,
		    uint64_t req_oid);
int sd_resolve_vid(struct sd_queue_ctx *ctx, struct sd_vdi *sd_vdi,
		   uint32_t idx, uint32_t *vid);
int sd_update_vid(struct sd_queue_ctx *ctx, struct sd_vdi *sd_vdi,
		  uint32_t idx, uint32_t *vid);
int sd_exec_read(struct sd_queue_ctx *ctx, struct sd_vdi *sd_vdi,
		 struct sd_request *sd_io);
int sd_exec_discard(struct sd_queue_ctx *ctx, struct sd_vdi *sd_vdi,
		    struct sd_request *sd_io);
int sd_exec_write(struct sd_queue_ctx *ctx, struct sd_vdi *sd_vdi,
		  struct sd_request *sd_io);

#ifdef __cplusplus
}
#endif
#endif /* __SHEEP_H__ */
