// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include <linux/falloc.h>
#include <stdlib.h>

#include "ublksrv_tgt.h"
#include "sheep.h"

struct sheepdog_tgt_data {
	char cluster_host[256];
	char cluster_port[16];
	char vdi_name[256];
	unsigned long vid;
	bool user_copy;
	bool auto_zc;
	bool zero_copy;
};

static int sheepdog_setup_tgt(struct ublksrv_dev *dev, int type)
{
	struct ublksrv_tgt_info *tgt = &dev->tgt;
	const struct ublksrv_ctrl_dev *cdev =
		ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int ret;
	struct ublk_params p;
	struct sheepdog_tgt_data *tgt_data =
		(struct sheepdog_tgt_data*)dev->tgt.tgt_data;

	ret = ublk_json_read_target_str_info(cdev, "vdi_name",
					     tgt_data->vdi_name);
	if (ret < 0) {
		ublk_err( "%s: read vdi name failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "vid",
			&tgt_data->vid);
	if (ret) {
		ublk_err( "%s: read vdi id failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_host",
					     tgt_data->cluster_host);
	if (ret) {
		ublk_err( "%s: read hostname failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_port",
					     tgt_data->cluster_port);
	if (ret) {
		ublk_err( "%s: read port id failed, error %d\n",
				__func__, ret);
		return ret;
	}
	ret = ublk_json_read_params(&p, cdev);
	if (ret) {
		ublk_err( "%s: read ublk params failed %d\n",
				__func__, ret);
		return ret;
	}

	ublksrv_tgt_set_io_data_size(tgt);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	tgt_data->auto_zc = info->flags & UBLK_F_AUTO_BUF_REG;
	tgt_data->zero_copy = info->flags & UBLK_F_SUPPORT_ZERO_COPY;
	tgt_data->user_copy = info->flags & UBLK_F_USER_COPY;
	if (tgt_data->zero_copy || tgt_data->user_copy)
		tgt->tgt_ring_depth *= 2;

	return 0;
}

static int sheepdog_recover_tgt(struct ublksrv_dev *dev, int type)
{
	dev->tgt.tgt_data = calloc(1, sizeof(struct sheepdog_tgt_data));

	return sheepdog_setup_tgt(dev, type);
}

static int sheepdog_init_tgt(struct ublksrv_dev *dev, int type, int argc, char
		*argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	static const struct option sheepdog_longopts[] = {
		{ "host",	required_argument, NULL, 'h'},
		{ "port",	required_argument, NULL, 'p'},
		{ "name",	required_argument, NULL, 'n' },
		{ "lbs",	required_argument, NULL, 'b'},
		{ NULL }
	};
	int fd, opt, lbs, ret;
	char *vdi_name = NULL;
	char *cluster_host = NULL, *cluster_port = NULL;
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD |
			UBLK_PARAM_TYPE_DMA_ALIGN,
		.basic = {
			.attrs                  = UBLK_ATTR_VOLATILE_CACHE | UBLK_ATTR_FUA,
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= UINT_MAX >> 9,
			.max_discard_segments	= 1,
		},
		.dma = {
			.alignment = 511,
		},
	};
	bool can_discard = false;
	uint32_t vid;

	if (ublksrv_is_recovering(cdev))
		return sheepdog_recover_tgt(dev, 0);

	strcpy(tgt_json.name, "sheepdog");

	while ((opt = getopt_long(argc, argv, "h:p:n:b:",
				  sheepdog_longopts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			vdi_name = strdup(optarg);
			break;
		case 'b':
			errno = 0;
			lbs = strtoul(optarg, NULL, 10);
			if (lbs == ULONG_MAX && errno)
				return -EINVAL;
			if (lbs < 9)
				return -EINVAL;
			break;
		case 'h':
			cluster_host = strdup(optarg);
			break;
		case 'p':
			cluster_port = strdup(optarg);
			break;
		}
	}

	if (!vdi_name) {
		errno = ENOMEM;
		ret = -1;
		goto out_free;
	}

	if (!cluster_host)
		cluster_host = strdup("127.0.0.1");
	if (!cluster_port)
		cluster_port = strdup("7000");
	fd = connect_to_sheep(cluster_host, cluster_port);
	if (fd < 0) {
		ublk_err( "%s: cannot connect to sheepdog cluster\n",
			  __func__);
		ret = fd;
		goto out_free;
	}

	ret = sheepdog_vdi_lookup(fd, vdi_name, &vid);
	if (ret < 0) {
		ublk_err( "%s: failed to get VDI id for '%s'\n",
			  __func__, vdi_name);
		close(fd);
		goto out_free;
	}

	ret = sheepdog_read_params(fd, vid, &p);
	close(fd);
	if (ret < 0) {
		ublk_err( "%s: failed to read params for VID %x\n",
			  __func__, vid);
		goto out_free;
	}
	if (lbs) {
		if (lbs > p.basic.physical_bs_shift) {
			ublk_err( "%s: logical block size %d too large\n",
				  __func__, lbs);
			return -EINVAL;
		}
		p.basic.logical_bs_shift = lbs;
	}
	tgt_json.dev_size = p.basic.dev_sectors << 9;

	if (can_discard)
		p.discard.discard_granularity = p.basic.chunk_sectors;
	else
		p.types &= ~UBLK_PARAM_TYPE_DISCARD;

	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "sheepdog_host", cluster_host);
	ublk_json_write_tgt_str(cdev, "sheepdog_port", cluster_port);
	ublk_json_write_tgt_str(cdev, "vdi_name", vdi_name);
	ublk_json_write_tgt_long(cdev, "vid", vid);
	ublk_json_write_params(cdev, &p);

	dev->tgt.tgt_data = calloc(sizeof(struct sheepdog_tgt_data), 1);

	ret = sheepdog_setup_tgt(dev, type);
out_free:
	if (cluster_host)
		free(cluster_host);
	if (cluster_port)
		free(cluster_port);
	return ret;
}

static int sheepdog_init_queue(struct ublksrv_queue *q)
{
	struct ublksrv_tgt_info *tgt = &q->dev->tgt;
	struct sheepdog_tgt_data *tgt_data =
		(struct sheepdog_tgt_data *)tgt->tgt_data;
	struct sheepdog_queue_ctx *q_ctx;
	int fd, ret;

	q_ctx = (struct sheepdog_queue_ctx *)calloc(1, sizeof(struct sheepdog_queue_ctx));
	if (!q_ctx)
		return -ENOMEM;

	ret = sheep_allocate_context(q_ctx, tgt_ring_depth);
	if (ret < 0) {
		free(q_ctx);
		return -ENOMEM;
	}
	fd = connect_to_sheep(tgt_data->cluster_host,
			      tgt_data->cluster_port);
	if (fd < 0) {
		free(q_ctx);
		return fd;
	}
	q_ctx->fd = fd;
	
	return 0;
}

static inline int sheepdog_fallocate_mode(const struct ublksrv_io_desc *iod)
{
       __u16 ublk_op = ublksrv_get_op(iod);
       __u32 flags = ublksrv_get_flags(iod);
       int mode = FALLOC_FL_KEEP_SIZE;

       /* follow logic of linux kernel sheepdog */
       if (ublk_op == UBLK_IO_OP_DISCARD) {
               mode |= FALLOC_FL_PUNCH_HOLE;
       } else if (ublk_op == UBLK_IO_OP_WRITE_ZEROES) {
               if (flags & UBLK_IO_F_NOUNMAP)
                       mode |= FALLOC_FL_ZERO_RANGE;
               else
                       mode |= FALLOC_FL_PUNCH_HOLE;
       } else {
               mode |= FALLOC_FL_ZERO_RANGE;
       }

       return mode;
}

static inline void sheepdog_rw_handle_fua(struct io_uring_sqe *sqe,
		const struct ublksrv_io_desc *iod)
{
	if (ublksrv_get_op(iod) == UBLK_IO_OP_WRITE &&
	    (iod->op_flags & UBLK_IO_F_FUA))
		sqe->rw_flags |= RWF_DSYNC;
}

static int sheepdog_rw_user_copy(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *tgt_data)
{
	unsigned ublk_op = ublksrv_get_op(iod);
	struct io_uring_sqe *sqe[2];
	__u64 pos = ublk_pos(q->q_id, tag, 0);
	void *buf = ublksrv_queue_get_io_buf(q, tag);

	ublk_queue_alloc_sqes(q, sqe, 2);
	if (ublk_op == UBLK_IO_OP_READ) {
		/* read from backing file to io buffer */
		io_uring_prep_read(sqe[0], 1 /*fds[1]*/,
				buf,
				iod->nr_sectors << 9,
				iod->start_sector << 9);
		io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe[0]->user_data = build_user_data(tag, ublk_op, 0, 1);

		/* copy io buffer to ublkc device */
		io_uring_prep_write(sqe[1], 0 /*fds[0]*/,
				buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe[1], IOSQE_FIXED_FILE);
		/* bit63 marks us as tgt io */
		sqe[1]->user_data = build_user_data(tag, UBLK_USER_COPY_WRITE, 0, 1);
	} else {
		/* copy ublkc device data to io buffer */
		io_uring_prep_read(sqe[0], 0 /*fds[0]*/,
			buf, iod->nr_sectors << 9, pos);
		io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE | IOSQE_IO_LINK);
		sqe[0]->user_data = build_user_data(tag, UBLK_USER_COPY_READ, 0, 1);

		/* write data in io buffer to backing file */
		io_uring_prep_write(sqe[1], 1 /*fds[1]*/,
			buf, iod->nr_sectors << 9,
			iod->start_sector << 9);
		io_uring_sqe_set_flags(sqe[1], IOSQE_FIXED_FILE);
		sheepdog_rw_handle_fua(sqe[1], iod);
		/* bit63 marks us as tgt io */
		sqe[1]->user_data = build_user_data(tag, ublk_op, 0, 1);
	}
	return 2;
}

static int sheepdog_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *tgt_data)
{
	enum io_uring_op uring_op = ublk_to_uring_fs_op(iod, tgt_data->auto_zc);
	void *buf = tgt_data->auto_zc ? NULL : (void *)iod->addr;
	struct io_uring_sqe *sqe[1];
	int ublk_op = ublksrv_get_op(iod);

	sheep_queue_rw(tgt_data, sd_io, iod, tag);
	sheepdog_rw_handle_fua(sqe[0], iod);
	return 1;
}

static int sheepdog_rw_zero_copy(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *tgt_data)
{
	unsigned ublk_op = ublksrv_get_op(iod);
	enum io_uring_op uring_op = ublk_to_uring_fs_op(iod, true);
	struct io_uring_sqe *sqe[3];

	ublk_queue_alloc_sqes(q, sqe, 3);

	io_uring_prep_buf_register(sqe[0], 0, tag, q->q_id, tag);
	sqe[0]->user_data = build_user_data(tag,
			ublk_cmd_op_nr(UBLK_U_IO_REGISTER_IO_BUF),
			0,
			1);
	sqe[0]->flags |= IOSQE_CQE_SKIP_SUCCESS | IOSQE_FIXED_FILE | IOSQE_IO_LINK;

	io_uring_prep_rw(uring_op,
			sqe[1],
			1 /*fds[1]*/,
			0,
			iod->nr_sectors << 9,
			iod->start_sector << 9);
	sqe[1]->buf_index = tag;
	sqe[1]->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
	sqe[1]->user_data = build_user_data(tag, ublk_op, 0, 1);

	io_uring_prep_buf_unregister(sqe[2], 0, tag, q->q_id, tag);
	sqe[2]->flags |= IOSQE_FIXED_FILE;
	sqe[2]->user_data = build_user_data(tag,
			ublk_cmd_op_nr(UBLK_U_IO_UNREGISTER_IO_BUF),
			0,
			1);

	// buf register is marked as IOSQE_CQE_SKIP_SUCCESS
	return 2;
}

static int sheepdog_queue_tgt_rw(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *data)
{
	/* auto_zc has top priority */
	if (data->auto_zc)
		return sheepdog_rw(q, iod, tag, data);
	if (data->zero_copy)
		return sheepdog_rw_zero_copy(q, iod, tag, data);
	if (data->user_copy)
		return sheepdog_rw_user_copy(q, iod, tag, data);
	return sheepdog_rw(q, iod, tag, data);
}

static int sheepdog_handle_flush(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag)
{
	struct io_uring_sqe *sqe[1];
	unsigned ublk_op = ublksrv_get_op(iod);

	ublk_queue_alloc_sqes(q, sqe, 1);
	io_uring_prep_fsync(sqe[0],
			1 /*fds[1]*/,
			IORING_FSYNC_DATASYNC);
	io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE);
	/* bit63 marks us as tgt io */
	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, 1);

	return 1;
}

static int sheepdog_handle_discard(const struct ublksrv_queue *q,
		const struct ublksrv_io_desc *iod, int tag,
		const struct sheepdog_tgt_data *data)
{
	struct io_uring_sqe *sqe[1];
	unsigned ublk_op = ublksrv_get_op(iod);

	ublk_queue_alloc_sqes(q, sqe, 1);
	io_uring_prep_fallocate(sqe[0], 1 /*fds[1]*/,
				sheepdog_fallocate_mode(iod),
				iod->start_sector << 9,
				iod->nr_sectors << 9);
	io_uring_sqe_set_flags(sqe[0], IOSQE_FIXED_FILE);
	/* bit63 marks us as tgt io */
	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, 1);
	return 1;
}

static int sheepdog_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	const struct sheepdog_tgt_data *tgt_data =
		(struct sheepdog_tgt_data*) q->dev->tgt.tgt_data;
	int ret;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ret = sheepdog_handle_flush(q, iod, tag);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		ret = sheepdog_handle_discard(q, iod, tag, tgt_data);
		break;
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
		ret = sheepdog_queue_tgt_rw(q, iod, tag, tgt_data);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
			iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	return ret;
}

static co_io_job __sheepdog_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data, int tag)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	int ret;

 again:
	ret = sheepdog_queue_tgt_io(q, data, tag);
	if (ret > 0) {
		int io_res = 0;
		while (ret-- > 0) {
			int res;

			co_await__suspend_always(tag);
			res = ublksrv_tgt_process_cqe(io, &io_res);
			if (res < 0 && io_res >= 0)
				io_res = res;
		}
		if (io_res == -EAGAIN)
			goto again;
		ublksrv_complete_io(q, tag, io_res);
	} else if (ret < 0) {
		ublk_err( "fail to queue io %d, ret %d\n", tag, tag);
	} else {
		ublk_err( "no sqe %d\n", tag);
	}
}

static int sheepdog_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	if (ublksrv_get_op(data->iod) == UBLK_IO_OP_DISCARD) {
		__u64 r[2];
		int res;

		io_uring_submit(q->ring_ptr);

		r[0] = data->iod->start_sector << 9;
		r[1] = data->iod->nr_sectors << 9;
		res = ioctl(q->dev->tgt.fds[1], BLKDISCARD, &r);
		ublksrv_complete_io(q, data->tag, res);
	} else {
		io->co = __sheepdog_handle_io_async(q, data, data->tag);
	}
	return 0;
}

static void sheepdog_tgt_io_done(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		const struct io_uring_cqe *cqe)
{
	ublksrv_tgt_io_done(q, data, cqe);
}

static void sheepdog_deinit_tgt(const struct ublksrv_dev *dev)
{
	fsync(dev->tgt.fds[1]);
	close(dev->tgt.fds[1]);
	free(dev->tgt.tgt_data);
}

static void sheepdog_cmd_usage()
{
	printf("\t-f backing_file [--buffered_io]\n");
	printf("\t\tdefault is direct IO to backing file\n");
}

static const struct ublksrv_tgt_type  sheepdog_tgt_type = {
	.handle_io_async = sheepdog_handle_io_async,
	.tgt_io_done = sheepdog_tgt_io_done,
	.usage_for_add = sheepdog_cmd_usage,
	.init_tgt = sheepdog_init_tgt,
	.init_queue = sheepdog_init_queue,
	.deinit_tgt =  sheepdog_deinit_tgt,
	.name	=  "sheepdog",
};

int main(int argc, char *argv[])
{
	return ublksrv_main(&sheepdog_tgt_type, argc, argv);
}
