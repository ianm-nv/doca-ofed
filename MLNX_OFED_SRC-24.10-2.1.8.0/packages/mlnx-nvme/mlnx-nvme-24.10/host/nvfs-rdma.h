/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2021 NVIDIA Corporation.
 */

#ifndef NVFS_RDMA_H
#define NVFS_RDMA_H

static bool nvme_rdma_nvfs_unmap_data(struct ib_device *ibdev,
		struct request *rq)

{
	struct nvme_rdma_request *req = blk_mq_rq_to_pdu(rq);
	enum dma_data_direction dma_dir = rq_dma_dir(rq);
	int count;

	if (!blk_integrity_rq(rq) && nvfs_ops != NULL) {
		count = nvfs_ops->nvfs_dma_unmap_sg(ibdev->dma_device, req->data_sgl.sg_table.sgl, req->data_sgl.nents,
				dma_dir);
		if (count) {
			nvfs_put_ops();
#ifdef HAVE_SG_ALLOC_TABLE_CHAINED_NENTS_FIRST_CHUNK_PARAM
			sg_free_table_chained(&req->data_sgl.sg_table, NVME_INLINE_SG_CNT);
#else
			sg_free_table_chained(&req->data_sgl.sg_table, true);
#endif

			return true;
		}
	}
	return false;
}

static int nvme_rdma_nvfs_map_data(struct ib_device *ibdev, struct request *rq, bool *is_nvfs_io, int* count)
{
	struct nvme_rdma_request *req = blk_mq_rq_to_pdu(rq);
	enum dma_data_direction dma_dir = rq_dma_dir(rq);
	int ret = 0;

	*is_nvfs_io = false;
	*count = 0;
	if (!blk_integrity_rq(rq) && nvfs_get_ops()) {

		// associates bio pages to scatterlist
		*count = nvfs_ops->nvfs_blk_rq_map_sg(rq->q, rq , req->data_sgl.sg_table.sgl);
		if (!*count) {
			nvfs_put_ops();
			return 0; // fall to cpu path
		}

		*is_nvfs_io = true;
		if (unlikely((*count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			pr_err("%s: failed to map sg_nents=:%d\n", __func__, req->data_sgl.nents);
			return -EIO;
		}
		req->data_sgl.nents = *count;

		*count = nvfs_ops->nvfs_dma_map_sg_attrs(ibdev->dma_device,
				req->data_sgl.sg_table.sgl,
				req->data_sgl.nents,
				dma_dir,
				DMA_ATTR_NO_WARN);

		if (unlikely((*count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			return -EIO;
		}

		if (unlikely(*count == NVFS_CPU_REQ)) {
			nvfs_put_ops();
			BUG();
			return -EIO;
		}

		return ret;
	} else {
		// Fall to CPU path
		return 0;
	}

	return ret;
}

#endif
