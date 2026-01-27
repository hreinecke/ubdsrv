// SPDX-License-Identifier: GPL-2.0

#ifndef __SHEEP_H__
#define __SHEEP_H__

#ifdef __cplusplus
extern "C" {
#endif

struct sheepdog_vdi {
	char vdi_name[256];
	uint32_t vid;
	pthread_mutex_t inode_lock;
	struct sd_inode inode;
};

struct sheepdog_queue_ctx {
	int fd;
	int num_ctx;
	struct sd_io_context *ctxs;
};

enum sd_io_type {
	SHEEP_READ,
	SHEEP_WRITE,
	SHEEP_CREATE,
	SHEEP_DISCARD,
};

struct sd_io_context {
	enum sd_io_type type;
	struct sd_req req;
	struct sd_rsp rsp;
	void *addr;
};

int connect_to_sheep(const char *cluster_host, const char *cluster_port);
int sheepdog_vdi_lookup(int fd, struct sheepdog_vdi *vdi, const char *vdi_name);
int sheepdog_vdi_release(int fd, struct sheepdog_vdi *vdi);
int sheepdog_read_inode(int fd, struct sheepdog_vdi *vdi);
int sheepdog_allocate_context(struct sheepdog_queue_ctx *q_ctx, int num_ctx);
void sheepdog_free_context(struct sheepdog_queue_ctx *q_ctx);
int sheepdog_rw(const struct ublksrv_queue *q,
		struct sheepdog_vdi *sd_vdi,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, int tag);
int sheepdog_discard(const struct ublksrv_queue *q,
		     const struct ublksrv_io_desc *iod,
		     struct sd_io_context *sd_io, int tag);

#ifdef __cplusplus
}
#endif
#endif /* __SHEEP_H__ */
