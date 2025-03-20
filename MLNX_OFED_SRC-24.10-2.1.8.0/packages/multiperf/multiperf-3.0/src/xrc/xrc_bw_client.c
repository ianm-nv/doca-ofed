#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include "common.h"
#include <signal.h>
#include <sys/wait.h>

struct test_ctx *global_ctx;

int create_send_qps(struct test_ctx *ctx) {
    struct ibv_qp_init_attr_ex init;
    struct ibv_qp_attr mod;
    int i;

    for (i = 0; i < ctx->num_of_qps; i++) {
        /* Create QP */
        memset(&init, 0, sizeof init);
        init.qp_type = IBV_QPT_XRC_SEND;
        init.send_cq = ctx->cq;
        init.cap.max_send_wr = 1000;
        init.cap.max_send_sge = 30;  // unknown limit (for 32 it fails)
        init.comp_mask = IBV_QP_INIT_ATTR_PD;
        init.pd = ctx->pd;

        ctx->qps[i] = ibv_create_qp_ex(ctx->ctx, &init);
        if (!ctx->qps[i]) {
            fprintf(stderr, "Couldn't create send QP[%d] errno %d\n", i, errno);
            return 1;
        }

        mod.qp_state = IBV_QPS_INIT;
        mod.pkey_index = 0;
        mod.port_num = ctx->ib_port;
        mod.qp_access_flags = 0;

        if (ibv_modify_qp(ctx->qps[i], &mod,
            IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT
            | IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify send QP[%d] to INIT\n", i);
        return 1;
            }
    }
    printf("Process %d:    %d SEND QPs were created.\n", getpid(), ctx->num_of_qps);

    return 0;
}

int init_ib_resources(struct test_ctx *ctx)
{
        ctx->dev_list = ibv_get_device_list(NULL);
        if (!ctx->dev_list) {
                perror("Failed to get IB devices list");
                return 1;
        }

        if (!ctx->ib_devname) {
                ctx->ib_dev = *ctx->dev_list;
                if (!ctx->ib_dev) {
                        fprintf(stderr, "No IB devices found\n");
                        return 1;
                }
        } else {
                int i;
                for (i = 0; ctx->dev_list[i]; ++i)
                        if (!strcmp(ibv_get_device_name(ctx->dev_list[i]), ctx->ib_devname))
                                break;
                ctx->ib_dev = ctx->dev_list[i];
                if (!ctx->ib_dev) {
                        fprintf(stderr, "IB device %s not found\n", ctx->ib_devname);
                        return 1;
                }
        }

        ctx->ctx = ibv_open_device(ctx->ib_dev);
        if (!ctx->ctx) {
                fprintf(stderr, "Couldn't get context for %s\n",
                        ibv_get_device_name(ctx->ib_dev));
                return 1;
        }

	ctx->device_name_by_id = ib_dev_name(ctx->ctx);
	if(ctx->device_name_by_id == DEVICE_ERROR) {
		fprintf(stderr, "Couldn't get device name\n");
		return 1;
	}

	if (ctx->mtu == IBV_MTU_4096 && (ctx->device_name_by_id == CONNECTX3 || ctx->device_name_by_id == CONNECTX3_PRO)) {
		ctx->mtu = IBV_MTU_2048;
	}

	if (ctx->verb == ATOMIC) {
		if (ctx->device_name_by_id == CONNECTIB || ctx->device_name_by_id == CONNECTX4) {
			ctx->masked_atomics = 1;
		}
	}

        ctx->pd = ibv_alloc_pd(ctx->ctx);
        if (!ctx->pd) {
                fprintf(stderr, "failed to allocate pd\n");
                return 1;
        }

	if (create_mr(ctx))
	{
		fprintf(stderr,"failed to create mr\n");
		return 1;
	}

        if (ibv_query_port(ctx->ctx, ctx->ib_port, &ctx->portinfo)) {
                fprintf(stderr, "Couldn't get port info\n");
                return 1;
        }

        if (ctx->user_mtu) {
            if (ctx->mtu > ctx->portinfo.active_mtu) {
                fprintf(stderr, "Requested MTU (%d) larget than port MTU (%d)\n", ctx->user_mtu, ctx->portinfo.active_mtu);
                return 1;
            }
        } else ctx->mtu = ctx->portinfo.active_mtu;

        int cq_size = ((ctx->tx_depth*ctx->num_of_qps*SRQ_UPPER_BOUND) > 65408) ? 65408 : ctx->tx_depth*ctx->num_of_qps*SRQ_UPPER_BOUND;
        ctx->cq = ibv_create_cq(ctx->ctx, cq_size, NULL, NULL, 0);
        if (!ctx->cq) {
                fprintf(stderr, "failed to create cq\n");
                return -1;
        }

	// init XRCD
	struct ibv_xrcd_init_attr xrcd_attr;

	memset(&xrcd_attr, 0, sizeof xrcd_attr);
	xrcd_attr.comp_mask = IBV_XRCD_INIT_ATTR_FD | IBV_XRCD_INIT_ATTR_OFLAGS;
	xrcd_attr.oflags = O_CREAT;
	ctx->xrcd = ibv_open_xrcd(ctx->ctx, &xrcd_attr);
	if (!ctx->xrcd) {
		fprintf(stderr, "Couldn't Open the XRC Domain %d\n", errno);
		return 1;
	}

	if(create_send_qps(ctx))
	{
		fprintf(stderr,"failed to create qps\n");
		return 1;
	}

	if (ibv_query_gid(ctx->ctx, ctx->ib_port, ctx->gid_index, &ctx->gid)) return 1;

	return 0;
}

int start_connection(char* servername, int port)
{
	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	int n;
	int sockfd = -1;

	if (asprintf(&service, "%d", port) < 0)
		return -1;

	n = getaddrinfo(servername, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
		free(service);
		return -1;
	}

	while (sockfd < 0)
	{
		for (t = res; t; t = t->ai_next) {
			sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
			if (sockfd >= 0) {
				if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
					break;

				close(sockfd);
				sockfd = -1;
			}
		}

	}

	return sockfd;
}

int send_data_to_server(int sock, struct test_ctx *ctx, int i)
{
	char msg[MSG_FORMAT_SIZE];
	sprintf(msg, MSG_FORMAT, ctx->qps[i]->qp_num, 0, ctx->portinfo.lid,
		(uint64_t)ctx->gid.global.subnet_prefix, (uint64_t)ctx->gid.global.interface_id,
		0, 0, ctx->gid_index, ctx->mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send local address\n");
		exit(1);
	}
	return 0;
}

int send_info_to_server(int sock, struct test_ctx *ctx)
{
	char msg[MSG_FORMAT_SIZE];
    sprintf(msg, MSG_FORMAT, ctx->num_of_qps, 0, 0, (uint64_t)0, (uint64_t)0, (uint32_t)0, 0, 0, ctx->mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send info to server\n");
		exit(1);
	}
	return 0;
}

int get_data_from_server(int sockfd, test_data *data)
{
	char msg[MSG_FORMAT_SIZE];
	uint64_t subnet_prefix = 0, interface_id = 0;
	int err = read(sockfd, msg, sizeof(msg));
	int tmp;

	if (err != sizeof(msg)) {
			perror("client read");
			fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
	exit(1);
	}

	sscanf(msg, MSG_FORMAT,&data->qp_num, &tmp, &data->lid,
		&subnet_prefix, &interface_id,
		&data->psn, &data->num_of_srqs, &data->gid_index , &data->mtu);

	data->gid.global.subnet_prefix = subnet_prefix;
	data->gid.global.interface_id = interface_id;
	return 0;
}

int get_srq_num_from_server(int sockfd,  struct test_ctx *ctx, int i)
{
	char msg[MSG_SRQ_NUM_FORMAT_SIZE];

	int err = read(sockfd, msg, sizeof(msg));

	if (err != sizeof(msg)) {
		perror("client read");
		fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
		exit(1);
	}

	sscanf(msg, MSG_FORMAT_SRQ_NUMBER, &ctx->srq_num_list[i], &ctx->remote_rkey[i], &ctx->remote_vaddr[i]);
	return 0;

}

int modify_to_rtr_rts(struct test_ctx *ctx, test_data *data)
{
	int i;
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		struct ibv_qp_attr attr = {
			.qp_state               = IBV_QPS_RTR,
			.dest_qp_num            = data[i].qp_num,
			.path_mtu               = ctx->mtu,
			.rq_psn                 = data[i].psn,
			.min_rnr_timer          = 12,
			.max_dest_rd_atomic     = ctx->out_reads,
			.ah_attr                = {
				.dlid           = data[i].lid,
				.sl             = ctx->sl,
				.port_num       = ctx->ib_port,
				.is_global      = 1,
				.grh.hop_limit  = 5,
				.grh.dgid  = data[i].gid,
				.grh.sgid_index  = data[i].gid_index,
				.src_path_bits  = 0
			}
		};

		if (ibv_modify_qp(ctx->qps[i], &attr,
				  IBV_QP_STATE              |
				  IBV_QP_AV                 |
				  IBV_QP_PATH_MTU           |
				  IBV_QP_DEST_QPN           |
				  IBV_QP_RQ_PSN             |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER)) {
			fprintf(stderr, "Failed to modify QP to RTR. errno: %d\n", errno);
			return 1;
		}
		attr.qp_state       = IBV_QPS_RTS;
		attr.timeout        = ctx->qp_timeout;
		attr.retry_cnt      = 7;
		attr.rnr_retry      = 7;
		attr.sq_psn         = data->psn;
		attr.max_rd_atomic  = ctx->out_reads;
		attr.ah_attr.is_global          = 1;
        attr.ah_attr.grh.hop_limit      = 0xFF;
        attr.ah_attr.grh.dgid           = data->gid;
        attr.ah_attr.grh.sgid_index     = ctx->gid_index;
        attr.ah_attr.grh.traffic_class  = ctx->tclass;
        attr.ah_attr.sl                 = ctx->sl;
		if (ibv_modify_qp(ctx->qps[i], &attr,
				  IBV_QP_STATE              |
				  IBV_QP_TIMEOUT            |
				  IBV_QP_RETRY_CNT          |
				  IBV_QP_RNR_RETRY          |
				  IBV_QP_SQ_PSN             |
				  IBV_QP_MAX_QP_RD_ATOMIC)) {
			fprintf(stderr, "Failed to modify QP to RTS. errno: %d\n", errno);
			return 1;
		}
	}

        return 0;
}

void catch_alarm(int sig)
{
        switch (global_ctx->state) {
                case START_STATE:
                        global_ctx->state = SAMPLE_STATE;
			if (gettimeofday(&global_ctx->start, NULL)) {
		                perror("gettimeofday");
                		return;
        		}
                        alarm(global_ctx->duration - 2*(global_ctx->margin));
                        break;
                case SAMPLE_STATE:
                        global_ctx->state = STOP_SAMPLE_STATE;
			if (gettimeofday(&global_ctx->end, NULL)) {
		                perror("gettimeofday");
                		return;
        		}

                        if (global_ctx->margin > 0)
                                alarm(global_ctx->margin);
                        else
                                catch_alarm(0);

                        break;
                case STOP_SAMPLE_STATE:
                        global_ctx->state = END_STATE;
                        break;
                default:
                        fprintf(stderr,"unknown state\n");
        }
}

// for each qp, build a linked list of wr. size(wr_list) = num of remote srqs.
// for this mode, the cq_mod feature is disabled (we get completion per wr).
int run_traffic_multiple_wr_per_qp(struct test_ctx *ctx, test_data *data)
{
	uint64_t totscnt = 0;
	uint64_t totccnt = 0;
	uint64_t *scnt;
	uint64_t *ccnt;
        struct ibv_send_wr *wr;
        struct ibv_send_wr *bad_wr;
        struct ibv_sge  *sg_list;
	int err;
	int i, j, cur_srq_num, wr_index;
	int ne;
	int poll_batch = 16*ctx->num_of_srqs;
	struct ibv_wc *wc = NULL;
	ALLOCATE(wr ,struct ibv_send_wr ,ctx->num_of_qps*ctx->num_of_srqs);
	ALLOCATE(wc ,struct ibv_wc ,poll_batch);
	ALLOCATE(sg_list ,struct ibv_sge ,ctx->num_of_qps);
	ALLOCATE(scnt ,uint64_t ,ctx->num_of_qps);
	ALLOCATE(ccnt ,uint64_t ,ctx->num_of_qps);

	global_ctx=ctx;
	global_ctx->state = START_STATE;
	signal(SIGALRM, catch_alarm);
	if (ctx->margin > 0 )
		alarm(ctx->margin);
	else
		catch_alarm(0); //move to next state

	ctx->iters = 0;
	// for each qp, build list of wrs (size(wr) = num of srqs).
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		// init vars per qp
		ccnt[i] = 0;
		scnt[i] = 0;
		sg_list[i].addr = ctx->my_addr[i];
		sg_list[i].length = ctx->size;
		sg_list[i].lkey = ctx->mrs[i]->lkey;

		for (j = 0; j < ctx->num_of_srqs; j++) {
			wr_index = i * ctx->num_of_srqs + j;
			// by default, rand the srq num. If got -R flag, take each time next srq (round robin).
			cur_srq_num = (ctx->round_robin_srqs) ? j : rand() % ctx->num_of_srqs;
			memset(&wr[wr_index], 0, sizeof(wr[wr_index]));
			wr[wr_index].num_sge = 1;

			if (ctx->verb == WRITE)
				wr[wr_index].opcode = IBV_WR_RDMA_WRITE;
			else if (ctx->verb == ATOMIC)
			{
				if(ctx->atomicType == CMP_AND_SWAP)
				{
					wr[wr_index].opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
					wr[wr_index].wr.atomic.swap = CMP_AND_SWAP;
				}
				else
				{
					wr[wr_index].opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
					wr[wr_index].wr.atomic.compare_add = FETCH_AND_ADD;
				}

				wr[wr_index].wr.atomic.remote_addr = ctx->remote_vaddr[cur_srq_num];
				wr[wr_index].wr.atomic.rkey = ctx->remote_rkey[cur_srq_num];

			}
			else if(ctx->verb == READ)
				wr[wr_index].opcode = IBV_WR_RDMA_READ;
			else if(ctx->verb == SEND)
				wr[wr_index].opcode = IBV_WR_SEND;

			wr[wr_index].send_flags = IBV_SEND_SIGNALED;
			wr[wr_index].sg_list = &sg_list[i];
			wr[wr_index].wr.rdma.remote_addr = ctx->remote_vaddr[cur_srq_num];
			wr[wr_index].wr.rdma.rkey = ctx->remote_rkey[cur_srq_num];
			wr[wr_index].wr_id = i;  // important in order to count the ccnt later.
			wr[wr_index].qp_type.xrc.remote_srqn = ctx->srq_num_list[cur_srq_num];

			if (ctx->size <= ctx->inl)
				wr[wr_index].send_flags |= IBV_SEND_INLINE;
		}

		// connect all wrs of the current qp.
		for (j = 0; j < ctx->num_of_srqs; j++) {
			wr_index = i * ctx->num_of_srqs + j;
			if (j == ctx->num_of_srqs - 1) {  // last node in list
				wr[wr_index].next = NULL;
			} else {  // connect to next node
				wr[wr_index].next = &wr[wr_index+1];
			}
		}
	}

	while (global_ctx->state != END_STATE)
	{
		for(i = 0; i < ctx->num_of_qps; i++)
		{
			while ( (scnt[i] - ccnt[i]) < ctx->tx_depth )
			{

				int wr_post_index = i * ctx->num_of_srqs;
				err = ibv_post_send(ctx->qps[i], &wr[wr_post_index], &bad_wr);
				if (err) {
					fprintf(stderr, "failed to post send request in iter: #%ld\n",ctx->iters + i);
					return -1;
				}

				totscnt += ctx->num_of_srqs;
				scnt[i] += ctx->num_of_srqs;

			}
		}

		if (totccnt < totscnt)
		{
			ne = ibv_poll_cq(ctx->cq, poll_batch, wc);
			if (ne > 0)
			{
				int j;
				for (j = 0; j < ne; j++)
				{
					if (wc[j].status != IBV_WC_SUCCESS) {
						fprintf(stderr, "completion with error %d\n", wc[j].status);
						return -1;
					}

					if (global_ctx->state == SAMPLE_STATE)
						ctx->iters += 1;

					ccnt[wc[j].wr_id] += 1;
					totccnt += 1;
				}
			}
			else if (ne < 0)
			{
				fprintf(stderr, "failed to poll cq\n");
				return -1;
			}
		}
        }

	print_bw_report(ctx);

	return 0;
}

// for each qp, build a single wr.
int run_traffic_single_wr_per_qp(struct test_ctx *ctx, test_data *data)
{
	uint64_t totscnt = 0;
	uint64_t totccnt = 0;
	uint64_t *scnt;
	uint64_t *ccnt;
        struct ibv_send_wr *wr;
        struct ibv_send_wr *bad_wr;
        struct ibv_sge  *sg_list;
	int err;
	int i, cur_srq_num, round_robin_srq;
	int ne;
	int poll_batch = 16;
	struct ibv_wc *wc = NULL;
	ALLOCATE(wr ,struct ibv_send_wr ,ctx->num_of_qps);
	ALLOCATE(wc ,struct ibv_wc ,poll_batch);
	ALLOCATE(sg_list ,struct ibv_sge ,ctx->num_of_qps);
	ALLOCATE(scnt ,uint64_t ,ctx->num_of_qps);
	ALLOCATE(ccnt ,uint64_t ,ctx->num_of_qps);

	global_ctx=ctx;
	global_ctx->state = START_STATE;
	signal(SIGALRM, catch_alarm);
	if (ctx->margin > 0 )
		alarm(ctx->margin);
	else
		catch_alarm(0); //move to next state

	ctx->iters = 0;
	round_robin_srq = 0;
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		// by default, rand the srq num. If got -R flag, take each time next srq (round robin).
		cur_srq_num = (ctx->round_robin_srqs) ? round_robin_srq : rand() % ctx->num_of_srqs;
		round_robin_srq = (round_robin_srq + 1) % ctx->num_of_srqs;
		ccnt[i] = 0;
		scnt[i] = 0;
		memset(&wr[i], 0, sizeof(wr[i]));
		wr[i].num_sge = 1;

		if (ctx->verb == WRITE)
			wr[i].opcode = IBV_WR_RDMA_WRITE;
		else if (ctx->verb == ATOMIC)
		{
			if(ctx->atomicType == CMP_AND_SWAP)
			{
				wr[i].opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
				wr[i].wr.atomic.swap = CMP_AND_SWAP;
			}
			else
			{
				wr[i].opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
				wr[i].wr.atomic.compare_add = FETCH_AND_ADD;
			}

			wr[i].wr.atomic.remote_addr = ctx->remote_vaddr[cur_srq_num];
			wr[i].wr.atomic.rkey = ctx->remote_rkey[cur_srq_num];

		}
		else if(ctx->verb == READ)
			wr[i].opcode = IBV_WR_RDMA_READ;
		else if(ctx->verb == SEND)
			wr[i].opcode = IBV_WR_SEND;

		wr[i].send_flags = IBV_SEND_SIGNALED;
		sg_list[i].addr = ctx->my_addr[i];
		sg_list[i].length = ctx->size;
		sg_list[i].lkey = ctx->mrs[i]->lkey;
		wr[i].sg_list = &sg_list[i];
		wr[i].wr.rdma.remote_addr = ctx->remote_vaddr[cur_srq_num];
		wr[i].wr.rdma.rkey = ctx->remote_rkey[cur_srq_num];
		wr[i].wr_id = i;
		wr[i].qp_type.xrc.remote_srqn = ctx->srq_num_list[cur_srq_num];

		if (ctx->size <= ctx->inl)
			wr[i].send_flags |= IBV_SEND_INLINE;
	}

	while (global_ctx->state != END_STATE)
	{
		for(i = 0; i < ctx->num_of_qps; i++)
		{
			while ( (scnt[i] - ccnt[i]) < ctx->tx_depth )
			{
				if (scnt[i] % ctx->cq_mod == 0 && ctx->cq_mod > 1)
					wr[i].send_flags &= ~IBV_SEND_SIGNALED;

				err = ibv_post_send(ctx->qps[i], &wr[i], &bad_wr);
				if (err) {
					fprintf(stderr, "failed to post send request in iter: #%ld\n",ctx->iters + i);
					return -1;
				}

				totscnt += 1;
				scnt[i] += 1;

				if (ctx->size <= (ctx->page_size / 2)) {
					if (ctx->do_random_addr)
					{
						increase_rand_loc_addr(wr[i].sg_list,ctx->size,scnt[i],ctx->my_addr[i],0,ctx->cache_line_size,ctx->page_size, rand());
						increase_rand_rem_addr(&wr[i],ctx->size,scnt[i],data[i].vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size, rand());
					}
					else
					{
						increase_loc_addr(wr[i].sg_list,ctx->size,scnt[i],ctx->my_addr[i],0,ctx->cache_line_size,ctx->page_size);
						increase_rem_addr(&wr[i],ctx->size,scnt[i],data[i].vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size);
					}
				}

				if (scnt[i]%ctx->cq_mod == (ctx->cq_mod - 1))
					wr[i].send_flags |= IBV_SEND_SIGNALED;
			}
		}

		if (totccnt < totscnt)
		{
			ne = ibv_poll_cq(ctx->cq, poll_batch, wc);
			if (ne > 0)
			{
				int j;
				for (j = 0; j < ne; j++)
				{
					if (wc[j].status != IBV_WC_SUCCESS) {
						fprintf(stderr, "completion with error %d\n", wc[j].status);
						return -1;
					}

					if (global_ctx->state == SAMPLE_STATE)
						ctx->iters += ctx->cq_mod;

					ccnt[wc[j].wr_id] += ctx->cq_mod;
					totccnt += ctx->cq_mod;
				}
			}
			else if (ne < 0)
			{
				fprintf(stderr, "failed to poll cq\n");
				return -1;
			}
		}
        }

	print_bw_report(ctx);

	return 0;
}

int destroy_resources(struct test_ctx *ctx)
{
	int test_result = 0;
	int i;

	// free resources allocated per srq.
	free(ctx->srq_num_list);
	free(ctx->remote_rkey);
	free(ctx->remote_vaddr);


	for (i = 0; i < ctx->num_of_qps; i++)
	{
		if (ibv_destroy_qp(ctx->qps[i]))
		{
			fprintf(stderr, "failed to destroy dct\n");
			test_result = 1;
		}
	}

	if (ibv_destroy_cq(ctx->cq)) {
		fprintf(stderr, "failed to destroy CQ\n");
		test_result = 1;
	}

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		if (ibv_dereg_mr(ctx->mrs[i])) {
			fprintf(stderr, "failed to deregister MR\n");
			test_result = 1;
		}

		if (!ctx->mr_per_qp)
			break;
	}

	if (ibv_dealloc_pd(ctx->pd)) {
                fprintf(stderr, "failed to deallocate PD\n");
                test_result = 1;
        }

	if (ctx->use_contig_pages == 0)
                free(ctx->addr);

	free(ctx->qps);
	free(ctx->my_addr);

	return test_result;
}

int init_qps_memory_client(struct test_ctx *ctx)
{
	ALLOCATE(ctx->qps,struct ibv_qp*,ctx->num_of_qps);
	ALLOCATE(ctx->mrs,struct ibv_mr*,ctx->num_of_qps);
	ALLOCATE(ctx->my_addr,uintptr_t,ctx->num_of_qps);
	return 0;
}

void print_client_pattern(struct test_ctx *ctx)
{
	fprintf(stdout, "\nClient Pattern: ");
	if (ctx->round_robin_srqs) fprintf(stdout, "Srq mode: Round-Robin, ");
	else fprintf(stdout, "Srq mode: Random, ");
	if (ctx->multiple_wr_client) fprintf(stdout, "multiple wr per qp\n\n");
	else fprintf(stdout, "single wr per qp\n\n");
}

int main(int argc, char *argv[])
{
	int sockfd = 0;
	struct test_ctx           ctx;
	test_data *data;
	test_data tmp_data;
	int pid = 0, i;

	init_ctx(&ctx, argc, argv, 1);
	init_qps_memory_client(&ctx);

	print_client_pattern(&ctx);

	if (ctx.processes > 1)
	{
		for(i = 0; i < ctx.processes; i++)
		{
			pid = fork();
			if (pid == 0) // child, then exit the loop
				break;
			else if (pid < 0)
			{
				fprintf(stderr,"could not create new process using fork()\n");
				return 1;
			}

		}
	}
	if (pid == 0)
	{
		if (init_ib_resources(&ctx))
		{
			fprintf(stderr,"could not init ib_resources\n");
			return 1;
		}

		sockfd = start_connection(ctx.servername, ctx.port);
		if (sockfd < 0)
		{
			fprintf(stderr,"could not connect to server\n");
			return 1;
		}

		//inform the server how many QPs we want to open
		send_info_to_server(sockfd, &ctx);

		//allocate test_data array to save all server info (for each qp)
		ALLOCATE(data,test_data,ctx.num_of_qps);

		//exchange test data with the server
		for (i = 0; i < ctx.num_of_qps; i++)
		{
			get_data_from_server(sockfd, &data[i]);
			send_data_to_server(sockfd, &ctx, i);
		}

		// allocate memory for the list of srq_nums got from server and for the remote rkeys & vaddrs.
		ctx.num_of_srqs = data[0].num_of_srqs;
		ALLOCATE(ctx.srq_num_list,uint32_t,ctx.num_of_srqs);
		ALLOCATE(ctx.remote_rkey,uint32_t,ctx.num_of_srqs);
		ALLOCATE(ctx.remote_vaddr,uint64_t,ctx.num_of_srqs);

		// set num_of_srqs got from server
		for (i=0; i < ctx.num_of_srqs; i++)
		{
			get_srq_num_from_server(sockfd, &ctx, i);
		}
		fprintf(stdout, "Process %d:    got %d srq numbers from server\n", getpid(), ctx.num_of_srqs);

		if (modify_to_rtr_rts(&ctx, data))
		{
			fprintf(stderr, "could not modify QP to RTS\n");
			return 1;
		}

		//handshake
		get_data_from_server(sockfd, &tmp_data);
		send_data_to_server(sockfd, &ctx, 0);

		if (ctx.multiple_wr_client) {
			if (run_traffic_multiple_wr_per_qp(&ctx, data))
			{
				fprintf(stderr,"could not finish traffic\n");
				return 1;
			}
		} else {
			if (run_traffic_single_wr_per_qp(&ctx, data))
			{
				fprintf(stderr,"could not finish traffic\n");
				return 1;
			}
		}

		//sync, to let the server know I am done
		send_info_to_server(sockfd, &ctx);
		if (destroy_resources(&ctx))
		{
			fprintf(stderr, "could not destroy all ib resources\n");
			return 1;
		}
		fprintf(stdout, "Process %d:    destroy_resources is done.\n", getpid());

		close(sockfd);
	}

	while (wait(NULL) > 0);

	return 0;
}
