// SPDX-License-Identifier: GPL-2.0

#ifndef __SHEEP_H__
#define __SHEEP_H__

#ifdef __cplusplus
extern "C" {
#endif

struct sheepdog_vdi {
	char cluster_host[256];
	char cluster_port[16];
	char vdi_name[256];
	uint32_t vid;
	struct sd_inode inode;
};

struct sheepdog_queue_ctx {
	int fd;
	int num_ctx;
	struct sd_io_context *ctxs;
};

struct sd_io_context {
	struct sd_req req;
	struct sd_rsp rsp;
	void *addr;
};

int connect_to_sheep(struct sheepdog_vdi *vdi);
int sheepdog_vdi_lookup(int fd, struct sheepdog_vdi *vdi);
int sheepdog_vdi_release(int fd, struct sheepdog_vdi *vdi);
int sheepdog_read_inode(int fd, struct sheepdog_vdi *vdi);
int sheepdog_allocate_context(struct sheepdog_queue_ctx *q_ctx, int num_ctx);
void sheepdog_free_context(struct sheepdog_queue_ctx *q_ctx);
int sheepdog_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod,
		struct sd_io_context *sd_io, int tag);
int sheepdog_discard(const struct ublksrv_queue *q,
		     const struct ublksrv_io_desc *iod,
		     struct sd_io_context *sd_io, int tag);

#ifdef __cplusplus
}
#endif
#endif /* __SHEEP_H__ */
