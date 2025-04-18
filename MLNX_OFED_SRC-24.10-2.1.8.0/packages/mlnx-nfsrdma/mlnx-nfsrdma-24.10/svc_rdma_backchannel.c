// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2015-2018 Oracle.  All rights reserved.
 *
 * Support for reverse-direction RPCs on RPC/RDMA (server-side).
 */

#include <linux/sunrpc/svc_rdma.h>

#include "xprt_rdma.h"
#ifdef HAVE_TRACE_RPCRDMA_H
#include <trace/events/rpcrdma.h>
#endif

/**
 * svc_rdma_handle_bc_reply - Process incoming backchannel Reply
 * @rqstp: resources for handling the Reply
 * @rctxt: Received message
 *
 */
void svc_rdma_handle_bc_reply(struct svc_rqst *rqstp,
			      struct svc_rdma_recv_ctxt *rctxt)
{
	struct svc_xprt *sxprt = rqstp->rq_xprt;
	struct rpc_xprt *xprt = sxprt->xpt_bc_xprt;
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);
	struct xdr_buf *rcvbuf = &rqstp->rq_arg;
	struct kvec *dst, *src = &rcvbuf->head[0];
	__be32 *rdma_resp = rctxt->rc_recv_buf;
	struct rpc_rqst *req;
	u32 credits;

#ifdef HAVE_XPRT_QUEUE_LOCK
	spin_lock(&xprt->queue_lock);
#elif defined HAVE_RPC_XPRT_RECV_LOCK
	spin_lock(&xprt->recv_lock);
#else /* HAVE_XPRT_PIN_RQST is undefined in this case */
	spin_lock_bh(&xprt->transport_lock);
#endif
	req = xprt_lookup_rqst(xprt, *rdma_resp);
	if (!req)
		goto out_unlock;

	dst = &req->rq_private_buf.head[0];
	memcpy(&req->rq_private_buf, &req->rq_rcv_buf, sizeof(struct xdr_buf));
	if (dst->iov_len < src->iov_len)
		goto out_unlock;
	memcpy(dst->iov_base, src->iov_base, src->iov_len);

	xprt_pin_rqst(req);

#ifdef HAVE_XPRT_QUEUE_LOCK
	spin_unlock(&xprt->queue_lock);
#else
	spin_unlock(&xprt->recv_lock);
#endif

	credits = be32_to_cpup(rdma_resp + 2);
	if (credits == 0)
		credits = 1;	/* don't deadlock */
	else if (credits > r_xprt->rx_buf.rb_bc_max_requests)
		credits = r_xprt->rx_buf.rb_bc_max_requests;
#if defined(HAVE_RPC_XPRT_RECV_LOCK)|| defined(HAVE_XPRT_QUEUE_LOCK)
	spin_lock(&xprt->transport_lock);
#endif
	xprt->cwnd = credits << RPC_CWNDSHIFT;
#if defined(HAVE_RPC_XPRT_RECV_LOCK)|| defined(HAVE_XPRT_QUEUE_LOCK)
	spin_unlock(&xprt->transport_lock);
#endif

#ifdef HAVE_XPRT_QUEUE_LOCK
	spin_lock(&xprt->queue_lock);
#else
	spin_lock(&xprt->recv_lock);
#endif
	xprt_complete_rqst(req->rq_task, rcvbuf->len);

	xprt_unpin_rqst(req);
	rcvbuf->len = 0;

out_unlock:
#ifdef HAVE_XPRT_QUEUE_LOCK
	spin_unlock(&xprt->queue_lock);
#elif defined HAVE_RPC_XPRT_RECV_LOCK
	spin_unlock(&xprt->recv_lock);
#else
	spin_unlock_bh(&xprt->transport_lock);
#endif
}

/* Send a reverse-direction RPC Call.
 *
 * Caller holds the connection's mutex and has already marshaled
 * the RPC/RDMA request.
 *
 * This is similar to svc_rdma_send_reply_msg, but takes a struct
 * rpc_rqst instead, does not support chunks, and avoids blocking
 * memory allocation.
 *
 * XXX: There is still an opportunity to block in svc_rdma_send()
 * if there are no SQ entries to post the Send. This may occur if
 * the adapter has a small maximum SQ depth.
 */
static int svc_rdma_bc_sendto(struct svcxprt_rdma *rdma,
			      struct rpc_rqst *rqst,
			      struct svc_rdma_send_ctxt *sctxt)
{
	int ret;
#ifdef HAVE_SVC_RDMA_PCL
	struct svc_rdma_pcl empty_pcl;

	pcl_init(&empty_pcl);
	ret = svc_rdma_map_reply_msg(rdma, sctxt, &empty_pcl, &empty_pcl,
				     &rqst->rq_snd_buf);
#else

	ret = svc_rdma_map_reply_msg(rdma, sctxt, NULL, &rqst->rq_snd_buf);
#endif
	if (ret < 0)
		return -EIO;

	/* Bump page refcnt so Send completion doesn't release
	 * the rq_buffer before all retransmits are complete.
	 */
	get_page(virt_to_page(rqst->rq_buffer));
	sctxt->sc_send_wr.opcode = IB_WR_SEND;
#ifdef HAVE_SVC_RDMA_PCL
	return svc_rdma_post_send(rdma, sctxt);
#else
	return svc_rdma_send(rdma, sctxt);
#endif
}

/* Server-side transport endpoint wants a whole page for its send
 * buffer. The client RPC code constructs the RPC header in this
 * buffer before it invokes ->send_request.
 */
static int
xprt_rdma_bc_allocate(struct rpc_task *task)
{
	struct rpc_rqst *rqst = task->tk_rqstp;
	size_t size = rqst->rq_callsize;
	struct page *page;

	if (size > PAGE_SIZE) {
		WARN_ONCE(1, "svcrdma: large bc buffer request (size %zu)\n",
			  size);
		return -EINVAL;
	}

	page = alloc_page(GFP_NOIO | __GFP_NOWARN);
	if (!page)
		return -ENOMEM;
	rqst->rq_buffer = page_address(page);

	rqst->rq_rbuffer = kmalloc(rqst->rq_rcvsize, GFP_NOIO | __GFP_NOWARN);
	if (!rqst->rq_rbuffer) {
		put_page(page);
		return -ENOMEM;
	}
	return 0;
}

static void
xprt_rdma_bc_free(struct rpc_task *task)
{
	struct rpc_rqst *rqst = task->tk_rqstp;

	put_page(virt_to_page(rqst->rq_buffer));
	kfree(rqst->rq_rbuffer);
}

static int
rpcrdma_bc_send_request(struct svcxprt_rdma *rdma, struct rpc_rqst *rqst)
{
	struct rpc_xprt *xprt = rqst->rq_xprt;
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);
	struct svc_rdma_send_ctxt *ctxt;
	__be32 *p;
	int rc;

	ctxt = svc_rdma_send_ctxt_get(rdma);
	if (!ctxt)
		goto drop_connection;

	p = xdr_reserve_space(&ctxt->sc_stream, RPCRDMA_HDRLEN_MIN);
	if (!p)
		goto put_ctxt;
	*p++ = rqst->rq_xid;
	*p++ = rpcrdma_version;
	*p++ = cpu_to_be32(r_xprt->rx_buf.rb_bc_max_requests);
	*p++ = rdma_msg;
	*p++ = xdr_zero;
	*p++ = xdr_zero;
	*p   = xdr_zero;

	rqst->rq_xtime = ktime_get();
	rc = svc_rdma_bc_sendto(rdma, rqst, ctxt);
	if (rc)
		goto put_ctxt;
	return 0;

put_ctxt:
	svc_rdma_send_ctxt_put(rdma, ctxt);

drop_connection:
	return -ENOTCONN;
}

/**
 * xprt_rdma_bc_send_request - Send a reverse-direction Call
 * @rqst: rpc_rqst containing Call message to be sent
 *
 * Return values:
 *   %0 if the message was sent successfully
 *   %ENOTCONN if the message was not sent
 */
#ifdef HAVE_XPRT_OPS_SEND_REQUEST_RQST_ARG
static int xprt_rdma_bc_send_request(struct rpc_rqst *rqst)
{
#else
static int xprt_rdma_bc_send_request(struct rpc_task *task)
{
	struct rpc_rqst *rqst = task->tk_rqstp;
#endif
	struct svc_xprt *sxprt = rqst->rq_xprt->bc_xprt;
	struct svcxprt_rdma *rdma =
		container_of(sxprt, struct svcxprt_rdma, sc_xprt);
	int ret;

	if (test_bit(XPT_DEAD, &sxprt->xpt_flags))
		return -ENOTCONN;

	ret = rpcrdma_bc_send_request(rdma, rqst);
	if (ret == -ENOTCONN)
#ifdef HAVE_SVC_XPRT_CLOSE
		svc_xprt_close(sxprt);
#else
		svc_close_xprt(sxprt);
#endif
	return ret;
}

static void
xprt_rdma_bc_close(struct rpc_xprt *xprt)
{
	xprt_disconnect_done(xprt);
	xprt->cwnd = RPC_CWNDSHIFT;
}

static void
xprt_rdma_bc_put(struct rpc_xprt *xprt)
{
	xprt_rdma_free_addresses(xprt);
	xprt_free(xprt);
}

static const struct rpc_xprt_ops xprt_rdma_bc_procs = {
	.reserve_xprt		= xprt_reserve_xprt_cong,
	.release_xprt		= xprt_release_xprt_cong,
	.alloc_slot		= xprt_alloc_slot,
	.free_slot		= xprt_free_slot,
	.release_request	= xprt_release_rqst_cong,
	.buf_alloc		= xprt_rdma_bc_allocate,
	.buf_free		= xprt_rdma_bc_free,
	.send_request		= xprt_rdma_bc_send_request,
#ifdef HAVE_RPC_XPRT_OPS_SET_RETRANS_TIMEOUT
	.set_retrans_timeout	= xprt_set_retrans_timeout_def,
#endif
#ifdef HAVE_RPC_XPRT_OPS_WAIT_FOR_REPLY_REQUEST
	.wait_for_reply_request	= xprt_wait_for_reply_request_def,
#endif
	.close			= xprt_rdma_bc_close,
	.destroy		= xprt_rdma_bc_put,
	.print_stats		= xprt_rdma_print_stats
};

static const struct rpc_timeout xprt_rdma_bc_timeout = {
	.to_initval = 60 * HZ,
	.to_maxval = 60 * HZ,
};

/* It shouldn't matter if the number of backchannel session slots
 * doesn't match the number of RPC/RDMA credits. That just means
 * one or the other will have extra slots that aren't used.
 */
static struct rpc_xprt *
xprt_setup_rdma_bc(struct xprt_create *args)
{
	struct rpc_xprt *xprt;
	struct rpcrdma_xprt *new_xprt;

	if (args->addrlen > sizeof(xprt->addr))
		return ERR_PTR(-EBADF);

	xprt = xprt_alloc(args->net, sizeof(*new_xprt),
			  RPCRDMA_MAX_BC_REQUESTS,
			  RPCRDMA_MAX_BC_REQUESTS);
	if (!xprt)
		return ERR_PTR(-ENOMEM);

	xprt->timeout = &xprt_rdma_bc_timeout;
	xprt_set_bound(xprt);
	xprt_set_connected(xprt);
	xprt->bind_timeout = 0;
	xprt->reestablish_timeout = 0;
	xprt->idle_timeout = 0;

	xprt->prot = XPRT_TRANSPORT_BC_RDMA;
	xprt->ops = &xprt_rdma_bc_procs;

	memcpy(&xprt->addr, args->dstaddr, args->addrlen);
	xprt->addrlen = args->addrlen;
	xprt_rdma_format_addresses(xprt, (struct sockaddr *)&xprt->addr);
	xprt->resvport = 0;

	xprt->max_payload = xprt_rdma_max_inline_read;

	new_xprt = rpcx_to_rdmax(xprt);
	new_xprt->rx_buf.rb_bc_max_requests = xprt->max_reqs;

	xprt_get(xprt);
	args->bc_xprt->xpt_bc_xprt = xprt;
	xprt->bc_xprt = args->bc_xprt;

	/* Final put for backchannel xprt is in __svc_rdma_free */
	xprt_get(xprt);
	return xprt;
}

struct xprt_class xprt_rdma_bc = {
	.list			= LIST_HEAD_INIT(xprt_rdma_bc.list),
	.name			= "rdma backchannel",
	.owner			= THIS_MODULE,
	.ident			= XPRT_TRANSPORT_BC_RDMA,
	.setup			= xprt_setup_rdma_bc,
};
