// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include <linux/falloc.h>
#include <stdlib.h>
#include <pthread.h>

#include "ublksrv_tgt.h"
#include "sheepdog_proto.h"
#include "sheep.h"

struct sheepdog_dev {
	char cluster_host[256];
	char cluster_port[16];
	struct sheepdog_vdi vdi;
};

static inline struct sd_io_context *
io_tgt_to_sd_io(const struct ublk_io_tgt *io)
{
	return (struct sd_io_context *)(io + 1);
}

static int sheepdog_setup_tgt(struct ublksrv_dev *ub_dev, int type)
{
	struct ublksrv_tgt_info *tgt = &ub_dev->tgt;
	const struct ublksrv_ctrl_dev *cdev =
		ublksrv_get_ctrl_dev(ub_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int ret;
	unsigned long vid;
	struct ublk_params p;
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)ub_dev->tgt.tgt_data;

	ret = ublk_json_read_target_str_info(cdev, "vdi_name",
					     dev->vdi.vdi_name);
	if (ret < 0) {
		ublk_err( "%s: read vdi name failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_ulong_info(cdev, "vid", &vid);
	if (ret) {
		ublk_err( "%s: read vdi id failed, error %d\n",
				__func__, ret);
		return ret;
	}
	dev->vdi.vid = vid;

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_host",
					     dev->cluster_host);
	if (ret) {
		ublk_err( "%s: read hostname failed, error %d\n",
				__func__, ret);
		return ret;
	}

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_port",
					     dev->cluster_port);
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

	tgt->io_data_size = sizeof(struct ublk_io_tgt) +
		sizeof(struct sd_io_context);
	tgt->dev_size = p.basic.dev_sectors << 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	return 0;
}

static int sheepdog_recover_tgt(struct ublksrv_dev *ub_dev, int type)
{
	ub_dev->tgt.tgt_data = calloc(1, sizeof(struct sheepdog_vdi));

	return sheepdog_setup_tgt(ub_dev, type);
}

static int sheepdog_init_tgt(struct ublksrv_dev *ub_dev, int type,
			     int argc, char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(ub_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	static const struct option sheepdog_longopts[] = {
		{ "host",	required_argument, NULL, 'h'},
		{ "port",	required_argument, NULL, 'p'},
		{ "vdi_name",	required_argument, NULL, 'v' },
		{ "lbs",	required_argument, NULL, 'b'},
		{ NULL }
	};
	int fd, opt, lbs = 0, ret;
	char *vdi_name = NULL;
	char *cluster_host = NULL, *cluster_port = NULL;
	struct sheepdog_dev *dev;
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

	if (ublksrv_is_recovering(cdev))
		return sheepdog_recover_tgt(ub_dev, 0);

	strcpy(tgt_json.name, "sheepdog");

	while ((opt = getopt_long(argc, argv, "h:p:v:b:",
				  sheepdog_longopts, NULL)) != -1) {
		switch (opt) {
		case 'v':
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
		ublk_err( "%s: no VDI name\n", __func__);
		ret = -EINVAL;
		goto out_free;
	}

	dev = (struct sheepdog_dev *)calloc(1, sizeof(*dev));
	pthread_mutex_init(&dev->vdi.inode_lock, NULL);
	strcpy(dev->vdi.vdi_name, vdi_name);
	if (!cluster_host)
		strcpy(dev->cluster_host, "127.0.0.1");
	else
		strcpy(dev->cluster_host, cluster_host);
	if (!cluster_port)
		strcpy(dev->cluster_port, "7000");
	else
		strcpy(dev->cluster_port, cluster_port);

	fd = connect_to_sheep(dev->cluster_host, dev->cluster_port);
	if (fd < 0) {
		ublk_err( "%s: cannot connect to sheepdog cluster\n",
			  __func__);
		ret = fd;
		goto out_free;
	}

	ret = sheepdog_vdi_lookup(fd, &dev->vdi);
	if (ret < 0) {
		ublk_err( "%s: failed to get VDI id for '%s'\n",
			  __func__, vdi_name);
		close(fd);
		goto out_free;
	}

	ret = sheepdog_read_inode(fd, &dev->vdi);
	close(fd);
	if (ret < 0) {
		ublk_err( "%s: failed to read params for VID %x\n",
			  __func__, dev->vdi.vid);
		goto out_free;
	}
	p.basic.chunk_sectors = SD_DATA_OBJ_SIZE;
	p.basic.physical_bs_shift = dev->vdi.inode.block_size_shift;
	p.basic.dev_sectors = dev->vdi.inode.vdi_size >> 9;
	p.discard.discard_granularity = p.basic.chunk_sectors;
	p.discard.max_discard_sectors = p.basic.chunk_sectors;
	if (lbs) {
		if (lbs > p.basic.physical_bs_shift) {
			ublk_err( "%s: logical block size %d too large\n",
				  __func__, lbs);
			return -EINVAL;
		}
		p.basic.logical_bs_shift = lbs;
	}
	tgt_json.dev_size = p.basic.dev_sectors << 9;
	ublk_json_write_dev_info(cdev);
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_tgt_str(cdev, "sheepdog_host",
				dev->cluster_host);
	ublk_json_write_tgt_str(cdev, "sheepdog_port",
				dev->cluster_port);
	ublk_json_write_tgt_str(cdev, "vdi_name",
				dev->vdi.vdi_name);
	ublk_json_write_tgt_long(cdev, "vid", dev->vdi.vid);
	ublk_json_write_params(cdev, &p);

	ub_dev->tgt.tgt_data = dev;

	ret = sheepdog_setup_tgt(ub_dev, type);
out_free:
	if (cluster_host)
		free(cluster_host);
	if (cluster_port)
		free(cluster_port);
	return ret;
}

static int sheepdog_init_queue(const struct ublksrv_queue *q,
			       void **queue_data_ptr)
{
	struct ublksrv_tgt_info *tgt =
		(struct ublksrv_tgt_info *)&q->dev->tgt;
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)tgt->tgt_data;
	struct sheepdog_queue_ctx *q_ctx;
	int fd;

	q_ctx = (struct sheepdog_queue_ctx *)
		calloc(1, sizeof(struct sheepdog_queue_ctx));
	if (!q_ctx)
		return -ENOMEM;

	fd = connect_to_sheep(dev->cluster_host, dev->cluster_port);
	if (fd < 0) {
		ublk_err("%s: failed to connect to sheepdog\n",
			 __func__);
		free(q_ctx);
		return fd;
	}
	q_ctx->fd = fd;
	*queue_data_ptr = (void *)q_ctx;
	return 0;
}

static void sheepdog_deinit_queue(const struct ublksrv_queue *q)
{
	struct ublksrv_tgt_info *tgt =
		(struct ublksrv_tgt_info *)&q->dev->tgt;
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)tgt->tgt_data;
	struct sheepdog_queue_ctx *q_ctx =
		(struct sheepdog_queue_ctx *)q->private_data;

	if (q->private_data) {
		sheepdog_vdi_release(q_ctx->fd, &dev->vdi);
		close(q_ctx->fd);
		free(q_ctx);
	}
}

static int sheepdog_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		struct ublk_io_tgt *io)
{
	struct sd_io_context *sd_io = io_tgt_to_sd_io(io);
	const struct ublksrv_io_desc *iod = data->iod;
	uint64_t total = iod->nr_sectors << 9;
	unsigned ublk_op = ublksrv_get_op(iod);
	int ret;

	if (ublk_op == UBLK_IO_OP_FLUSH)
		return 0;

	switch (ublk_op) {
	case UBLK_IO_OP_WRITE_ZEROES:
	case UBLK_IO_OP_DISCARD:
		ret = sheepdog_discard(q, iod, sd_io, data->tag);
		break;
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
		ret = sheepdog_rw(q, iod, sd_io, data->tag);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d opcode %x len %ld ret %d\n", __func__,
		 data->tag, sd_io->req.opcode, total, ret);
	return ret < 0 ? ret : total;
}

static int sheepdog_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	int ret;

	ret = sheepdog_queue_tgt_io(q, data, io);
	ublksrv_complete_io(q, data->tag, ret);
	return 0;
}

static void sheepdog_deinit_tgt(const struct ublksrv_dev *dev)
{
	struct sheepdog_vdi *vdi =
		(struct sheepdog_vdi *)dev->tgt.tgt_data;

	pthread_mutex_destroy(&vdi->inode_lock);
	free(vdi);
}

static void sheepdog_cmd_usage()
{
	printf("\t-v|--vdi_name vdi_name\n");
	printf("\t[-h|--host host] [-p|--port port]\n");
}

static const struct ublksrv_tgt_type  sheepdog_tgt_type = {
	.handle_io_async = sheepdog_handle_io_async,
	.usage_for_add = sheepdog_cmd_usage,
	.init_tgt = sheepdog_init_tgt,
	.deinit_tgt = sheepdog_deinit_tgt,
	.name	=  "sheepdog",
	.init_queue = sheepdog_init_queue,
	.deinit_queue = sheepdog_deinit_queue,
};

int main(int argc, char *argv[])
{
	return ublksrv_main(&sheepdog_tgt_type, argc, argv);
}
