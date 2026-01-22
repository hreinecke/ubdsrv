// SPDX-License-Identifier: GPL-2.0

#ifndef __SHEEP_H__
#define __SHEEP_H__

#ifdef __cplusplus
extern "C" {
#endif

struct sheepdog_tgt_data {
	char cluster_host[256];
	char cluster_port[16];
	char vdi_name[256];
	unsigned long vid;
	unsigned int block_size_shift;
};

struct sheepdog_queue_ctx {
	int fd;
	int num_ctx;
	struct sd_io_context *ctxs;
};

int connect_to_sheep(const char *addr, const char *port);
int sheepdog_vdi_lookup(int fd, const char *name, uint32_t *vid);
int sheepdog_read_params(int fd, uint32_t vdi_id, struct ublk_params *p);
int sheepdog_allocate_context(struct sheepdog_queue_ctx *q_ctx, int num_ctx);
void sheepdog_free_context(struct sheepdog_queue_ctx *q_ctx);
int sheepdog_rw(const struct ublksrv_queue *q,
		struct io_uring_sqe *sqe,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *data);
int sheepdog_discard(const struct ublksrv_queue *q,
		     struct io_uring_sqe *sqe,
		     const struct ublksrv_io_desc *iod, int tag,
		     const struct sheepdog_tgt_data *tgt_data);
  
#ifdef __cplusplus
}
#endif
#endif /* __SHEEP_H__ */
