// SPDX-License-Identifier: GPL-2.0-only
/*
 * ublk.sheepdog.cpp - UBLK device server for sheepdog
 *
 * Copyright (c) 2026 Hannes Reinecke, SUSE
 */

#include <config.h>

#include <poll.h>
#include <sys/epoll.h>
#include <linux/falloc.h>
#include <stdlib.h>
#include <pthread.h>
#include <uuid/uuid.h>

#include "ublksrv_tgt.h"
#include "sheepdog_proto.h"
#include "sheepdog.h"

#define SD_OBJECT_SIZE(v) (UINT32_C(1) << (v)->inode->header.block_size_shift)

struct sheepdog_dev {
	char sd_host[256];
	char vdi_name[256];
	struct sd_cluster *cluster;
	struct sd_vdi *vdi;
};

static inline struct sd_request *
io_tgt_to_sd_io(const struct ublk_io_tgt *io)
{
	return (struct sd_request *)(io + 1);
}

static int sheepdog_setup_tgt(struct ublksrv_dev *ub_dev, int type)
{
	struct ublksrv_tgt_info *tgt = &ub_dev->tgt;
	const struct ublksrv_ctrl_dev *cdev =
		ublksrv_get_ctrl_dev(ub_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int fd, ret;
	char vdi_name[256];
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)ub_dev->tgt.tgt_data;

	ret = ublk_json_read_target_str_info(cdev, "vdi_name", vdi_name);
	if (ret < 0) {
		ublk_err( "%s: read vdi name failed, error %d\n",
				__func__, ret);
		return ret;
	}
	strncpy(dev->vdi_name, vdi_name, 256);

	ret = ublk_json_read_target_str_info(cdev, "sheepdog_cluster",
					     dev->sd_host);
	if (ret) {
		ublk_err( "%s: read hostname failed, error %d\n",
				__func__, ret);
		return ret;
	}

	dev->cluster = sd_connect(dev->sd_host);
	if (fd < 0) {
		ublk_err( "%s: cannot connect to sheepdog cluster\n",
			  __func__);
		return fd;
	}

	dev->vdi = sd_vdi_open(dev->cluster, dev->vdi_name);
	if (!dev->vdi) {
		close(fd);
		return ret;
	}

	tgt->io_data_size = sizeof(struct ublk_io_tgt) +
		sizeof(struct sd_request);
	tgt->dev_size = dev->vdi->inode->header.vdi_size >> 9;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;
	tgt->extra_ios = 0;

	return 0;
}

static int sheepdog_recover_tgt(struct ublksrv_dev *ub_dev, int type)
{
	ub_dev->tgt.tgt_data =
		(struct sheepdog_dev *)calloc(1, sizeof(struct sheepdog_dev));
	if (!ub_dev->tgt.tgt_data)
		return -ENOMEM;
	return sheepdog_setup_tgt(ub_dev, type);
}

static int sheepdog_init_tgt(struct ublksrv_dev *ub_dev, int type,
			     int argc, char *argv[])
{
	const struct ublksrv_ctrl_dev *cdev = ublksrv_get_ctrl_dev(ub_dev);
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	int unlock = 0;
	static const struct option sheepdog_longopts[] = {
		{ "cluster",	required_argument, NULL, 'c'},
		{ "vdi_name",	required_argument, NULL, 'v' },
		{ "lbs",	required_argument, NULL, 'b'},
		{ "uuid",	required_argument, NULL, 'U'},
		{ "unlock",	no_argument, &unlock, 'u'},
		{ NULL }
	};
	int opt, lbs = 9, ret;
	char *vdi_name = NULL;
	uuid_t uuid;
	const char *sd_cluster = "127.0.0.1:7000";
	struct sheepdog_dev *dev;
	struct sd_inode_header *vdi_header;
	struct ublksrv_tgt_base_json tgt_json = { 0 };
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD |
			UBLK_PARAM_TYPE_DMA_ALIGN,
		.basic = {
			.attrs                  = UBLK_ATTR_FUA,
			.logical_bs_shift	= 9,
			.physical_bs_shift	= 12,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
			.max_sectors		= info->max_io_buf_bytes >> 9,
		},

		.discard = {
			.max_discard_sectors	= SD_DATA_OBJ_SIZE >> 9,
			.max_discard_segments	= 1,
		},
		.dma = {
			.alignment = 511,
		},
	};

	if (ublksrv_is_recovering(cdev))
		return sheepdog_recover_tgt(ub_dev, 0);

	strcpy(tgt_json.name, "sheepdog");
	uuid_clear(uuid);

	while ((opt = getopt_long(argc, argv, "c:v:b:U:",
				  sheepdog_longopts, NULL)) != -1) {
		switch (opt) {
		case 'v':
			vdi_name = optarg;
			break;
		case 'b':
			errno = 0;
			lbs = strtoul(optarg, NULL, 10);
			if (lbs == ULONG_MAX && errno)
				return -EINVAL;
			if (lbs < 9)
				return -EINVAL;
			break;
		case 'c':
			sd_cluster = optarg;
			break;
		case 'U':
			if (uuid_parse(optarg, uuid))
				return -EINVAL;
			break;
		}
	}

	if (!vdi_name) {
		ublk_err( "%s: no VDI name\n", __func__);
		return -EINVAL;
	}

	ublk_json_write_dev_info(cdev);
	ublk_json_write_tgt_str(cdev, "sheepdog_cluster", sd_cluster);
	ublk_json_write_tgt_str(cdev, "vdi_name", vdi_name);
	ublk_json_write_tgt_ulong(cdev, "logical_block_shift", lbs);

	ub_dev->tgt.tgt_data = (struct sheepdog_dev *)calloc(1, sizeof(*dev));
	if (!ub_dev->tgt.tgt_data)
		return -ENOMEM;
	dev = (struct sheepdog_dev *)ub_dev->tgt.tgt_data;

	ret = sheepdog_setup_tgt(ub_dev, type);
	if (ret < 0)
		return ret;

	ublk_json_write_tgt_ulong(cdev, "vid", dev->vdi->vid);
	ublk_json_write_tgt_ulong(cdev, "ctime", vdi_header->create_time);
	if (uuid_is_null(uuid) && SD_INODE_USE_UUID(vdi_header)) {
		memcpy((char *)uuid, &vdi_header->vm_clock_nsec, 8);
		memcpy((char *)(uuid + 8), &vdi_header->vm_state_size, 8);
	}
	if (!uuid_is_null(uuid)) {
		memcpy(p.uuid.uuid, uuid, 16);
		p.types |= UBLK_PARAM_TYPE_UUID;
	}
	p.basic.physical_bs_shift = vdi_header->block_size_shift;
	p.basic.chunk_sectors = 1 << (p.basic.physical_bs_shift - 9);
	p.basic.dev_sectors = vdi_header->vdi_size >> 9;
	p.discard.discard_granularity = p.basic.chunk_sectors;
	p.discard.max_discard_sectors = p.basic.chunk_sectors;
	if (lbs > 9) {
		if (lbs > p.basic.physical_bs_shift) {
			ublk_err( "%s: logical block size %d too large\n",
				  __func__, lbs);
			return -EINVAL;
		}
		p.basic.logical_bs_shift = lbs;
	}
	tgt_json.dev_size = p.basic.dev_sectors << 9;
	ublk_json_write_target_base(cdev, &tgt_json);
	ublk_json_write_params(cdev, &p);

	return ret;
}

static int sheepdog_init_queue(const struct ublksrv_queue *q,
			       void **queue_data_ptr)
{
	struct ublksrv_tgt_info *tgt =
		(struct ublksrv_tgt_info *)&q->dev->tgt;
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)tgt->tgt_data;
	struct sd_cluster *q_ctx;

	q_ctx = sd_connect(dev->sd_host);
	if (!q_ctx) {
		ublk_err("%s: failed to connect to sheepdog\n",
			 __func__);
		return -errno;
	}

	*queue_data_ptr = (void *)q_ctx;
	return 0;
}

static void sheepdog_deinit_queue(const struct ublksrv_queue *q)
{
	struct sd_cluster *q_ctx =
		(struct sd_cluster *)q->private_data;

	if (q->private_data) {
		sd_disconnect(q_ctx);
		free(q_ctx);
	}
}

static int sheepdog_queue_tgt_io(const struct ublksrv_queue *q,
		const struct ublk_io_data *data,
		struct ublk_io_tgt *io)
{
	struct sd_cluster *q_ctx =
		(struct sd_cluster *)q->private_data;
	struct sd_request *sd_req = io_tgt_to_sd_io(io);
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)q->dev->tgt.tgt_data;
	const struct ublksrv_io_desc *iod = data->iod;
	uint32_t object_size = SD_OBJECT_SIZE(dev->vdi);
	uint64_t offset = (uint64_t)iod->start_sector << 9;
	uint32_t total = iod->nr_sectors << 9;
	uint64_t start = offset % object_size;
	int ublk_op = ublksrv_get_op(iod);
	size_t len = object_size - start;
	int ret = 0;

	if (total > len) {
		ublk_err("%s: op %u access beyond object size off %lu total %u\n",
			 __func__, ublk_op, offset, total);
		return -EIO;
	}
	sd_req->tag = data->tag;
	sd_req->vdi = dev->vdi;
	switch (ublk_op) {
	case UBLK_IO_OP_WRITE:
		ret = sd_vdi_write(q_ctx, sd_req, (void *)iod->addr,
				   total, offset);
		if (ret < 0)
			ublk_err("%s: tag %u opcode %x ret %d\n",
				 __func__, sd_req->tag, ublk_op, ret);
		break;
	case UBLK_IO_OP_READ:
		ret = sd_vdi_read(q_ctx, sd_req, (void *)iod->addr,
				  total, offset);
		if (ret < 0)
			ublk_err("%s: tag %u opcode %x ret %d\n",
				 __func__, sd_req->tag, ublk_op, ret);
		break;
	case UBLK_IO_OP_DISCARD:
	case UBLK_IO_OP_WRITE_ZEROES:
		ret = sd_vdi_discard(q_ctx, sd_req,
				     UBLK_IO_OP_DISCARD ?
				     NULL : (void *)iod->addr, total, offset);
		if (ret < 0)
			ublk_err("%s: tag %u opcode %x ret %d\n",
				 __func__, sd_req->tag, ublk_op, ret);
		break;
	default:
		ublk_err("%s: tag %u op %u not supported\n",
			 __func__, data->tag, ublk_op);
		ret = -EOPNOTSUPP;
		break;
	}
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

static void sheepdog_deinit_tgt(const struct ublksrv_dev *ub_dev)
{
	struct sheepdog_dev *dev =
		(struct sheepdog_dev *)ub_dev->tgt.tgt_data;

	if (dev) {
		if (dev->vdi) {
			sd_vdi_close(dev->cluster, dev->vdi);
			dev->vdi = NULL;
		}
		if (dev->cluster) {
			sd_disconnect(dev->cluster);
			free(dev->cluster);
			dev->cluster = NULL;
		}
		free(dev);
	}
}

static void sheepdog_cmd_usage()
{
	printf("\t-v|--vdi_name vdi_name\n");
	printf("\t[-h|--host host] [-p|--port port]\n");
	printf("\t[-u|--unlock]\n");
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
