#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
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

struct dc_ctx *global_ctx;

int init_ib_resources(struct dc_ctx *ctx)
{
	int i;

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

        ctx->cq = ibv_create_cq(ctx->ctx, ctx->tx_depth*ctx->num_of_qps, NULL, NULL, 0);
        if (!ctx->cq) {
                fprintf(stderr, "failed to create cq\n");
                return -1;
        }


	for (i = 0 ; i < ctx->num_of_qps; i++)
	{
		struct ibv_qp_init_attr_ex attr = {
			.send_cq = ctx->cq,
			.recv_cq = ctx->cq,
			.cap     = {
				.max_send_wr  = ctx->tx_depth,
				.max_send_sge = 1,
			},
			.qp_type = IBV_EXP_QPT_DC_INI,
			.pd = ctx->pd,
			.comp_mask = IBV_QP_INIT_ATTR_PD,
			.cap.max_inline_data = ctx->inl,
		};
		ctx->qp[i] = ibv_create_qp_ex(ctx->ctx, &attr);
		if (!ctx->qp[i]) {
			fprintf(stderr, "failed to create qp\n");
			return -1;
		}
	}
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		ctx->my_addr[i] = (uintptr_t)ctx->addr + i*BUFF_SIZE(ctx->size, ctx->page_size);
	}

	return 0;
}

int start_connection(char* servername, int port)
{
	int rem_port;

	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	char msg[sizeof(MSG_FORMAT)];
	int n;
	int sockfd = -1;
	int err;

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

int get_data_from_server(int sockfd, test_data *data)
{
	char msg[MSG_FORMAT_SIZE];

	int err = read(sockfd, msg, sizeof(msg));
        if (err != sizeof(msg)) {
                perror("client read");
                fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
        }

	sscanf(msg, MSG_FORMAT,&data->dct_num, &data->dct_key, &data->lid, &data->psn, &data->rkey, &data->vaddr, &data->srqn, &data->gid_index , &data->mtu);
	//printf("dct_num=%x , dct_key=%x , mtu=%d\n",data->dct_num,data->dct_key, data->mtu);
	return 1;

}

int create_ah(struct dc_ctx *ctx, test_data *data)
{
	struct ibv_ah_attr      ah_attr;
	memset(&ah_attr, 0, sizeof(ah_attr));
        ah_attr.is_global     = 0;
        ah_attr.dlid          = data->lid;
        ah_attr.sl            = 0;
        ah_attr.src_path_bits = 0;
        ah_attr.port_num      = ctx->ib_port;
        ctx->ah = ibv_create_ah(ctx->pd, &ah_attr);
        if (!ctx->ah) {
                fprintf(stderr, "failed to create ah\n");
                return -1;
        }

	return 1;
}

int modify_to_rts(struct dc_ctx *ctx, test_data *data)
{
	int i;

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		struct ibv_exp_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = ctx->ib_port,
			.qp_access_flags = 0,
			.dct_key = data->dct_key,
		};

		if (ibv_exp_modify_qp(ctx->qp[i], &attr,
				      IBV_EXP_QP_STATE          |
				      IBV_EXP_QP_PKEY_INDEX     |
				      IBV_EXP_QP_PORT           |
				      IBV_EXP_QP_DC_KEY)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			return 1;
		}

		attr.qp_state           = IBV_QPS_RTR;
		attr.max_dest_rd_atomic = 0;
		attr.path_mtu           = (enum ibv_mtu)data->mtu;
		attr.ah_attr.is_global  = 0;
		attr.ah_attr.dlid               = data->lid;
		attr.ah_attr.port_num   = ctx->ib_port;
		attr.dct_key = data->dct_key;

		if (ibv_exp_modify_qp(ctx->qp[i], &attr, IBV_EXP_QP_STATE                  |
						      IBV_EXP_QP_PATH_MTU               |
						      IBV_EXP_QP_AV)) {
			fprintf(stderr, "Failed to modify QP to RTR\n");
			return 1;
		}

		attr.qp_state       = IBV_QPS_RTS;
		attr.timeout        = 14;
		attr.retry_cnt      = 7;
		attr.rnr_retry      = 7;
		attr.max_rd_atomic  = 1;
		if (ibv_exp_modify_qp(ctx->qp[i], &attr, IBV_EXP_QP_STATE  |
						      IBV_EXP_QP_TIMEOUT        |
						      IBV_EXP_QP_RETRY_CNT      |
						      IBV_EXP_QP_RNR_RETRY      |
						      IBV_EXP_QP_MAX_QP_RD_ATOMIC)) {
			fprintf(stderr, "Failed to modify QP to RTS\n");
			return 1;
		}
	}
	return 1;
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

int run_traffic(struct dc_ctx *ctx, test_data *data)
{
	uint64_t totscnt = 0;
	uint64_t totccnt = 0;
	uint64_t *scnt;
	uint64_t *ccnt;
        struct ibv_exp_send_wr *wr;
        struct ibv_exp_send_wr *bad_wr;
        struct ibv_sge  *sg_list;
	int err;
	int i;
	int num, ne;
	struct ibv_wc *wc = NULL;
	ALLOCATE(wr ,struct ibv_exp_send_wr ,ctx->num_of_qps);
	ALLOCATE(wc ,struct ibv_wc ,ctx->tx_depth);
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

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		ccnt[i] = 0;
		scnt[i] = 0;
		memset(&wr[i], 0, sizeof(wr[i]));
		wr[i].num_sge = 1;
		wr[i].exp_opcode = IBV_EXP_WR_RDMA_WRITE;
		wr[i].exp_send_flags = IBV_EXP_SEND_SIGNALED;
		sg_list[i].addr = ctx->my_addr[i];
		sg_list[i].length = ctx->size;
		sg_list[i].lkey = ctx->mr->lkey;
		wr[i].sg_list = &sg_list[i];
		wr[i].dc.ah = ctx->ah;
		wr[i].dc.dct_access_key = data->dct_key;
		wr[i].dc.dct_number = data->dct_num;
		wr[i].wr.rdma.remote_addr = data->vaddr;
		wr[i].wr.rdma.rkey = data->rkey;
		wr[i].wr_id = i;

		if (ctx->size <= ctx->inl)
		{
			wr[i].exp_send_flags |= IBV_EXP_SEND_INLINE;
		}
	}

	while (global_ctx->state != END_STATE)
	{
		int qp_index;
		for(qp_index = 0; qp_index < ctx->num_of_qps; qp_index++)
		{
			for (i=1 ; i <= ctx->tx_depth; i++)
			{
				if (i == ctx->tx_depth)
					wr[qp_index].exp_send_flags |= IBV_EXP_SEND_SIGNALED;
				else
					wr[qp_index].exp_send_flags &= ~IBV_EXP_SEND_SIGNALED;

				err = ibv_exp_post_send(ctx->qp[qp_index], &wr[qp_index], &bad_wr);
				if (err) {
					fprintf(stderr, "failed to post send request #%d\n",ctx->iters + i);
					return -1;
				}

				totscnt += 1;
				scnt[qp_index] += 1;

				if (ctx->size <= (ctx->page_size / 2)) {
					increase_loc_addr(wr[qp_index].sg_list,ctx->size,totscnt,ctx->my_addr[qp_index],0,ctx->cache_line_size,ctx->page_size);
					increase_exp_rem_addr(&wr[qp_index],ctx->size,totscnt,data->vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size);
				}
			}
		}

		num = ctx->tx_depth*ctx->num_of_qps;
		do {
			ne = ibv_poll_cq(ctx->cq, 16, wc);
			if (ne < 0) {
				fprintf(stderr, "failed to poll cq\n");
				return -1;
			}
			int j;
			for (j = 0; j < ne; j++)
			{
				if (wc[j].status != IBV_WC_SUCCESS) {
                 		       	fprintf(stderr, "completion with error %d\n", wc[j].status);
                        		return -1;
                		}

				if (global_ctx->state == SAMPLE_STATE)
					ctx->iters += ctx->tx_depth;

				ccnt[wc[j].wr_id] += ctx->tx_depth;
			}
			num -= ne*ctx->tx_depth;
			
		} while (num > 0);


		totccnt += ctx->tx_depth;
        }


	print_bw_report(ctx);
}

int destroy_resources(struct dc_ctx *ctx)
{
	int test_result = 0;
	int i;

	if (ibv_destroy_ah(ctx->ah)) {
		fprintf(stderr, "failed to destroy AH\n");
		test_result = 1;
	}

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		if (ibv_destroy_qp(ctx->qp[i])) {
			fprintf(stderr, "failed to destroy dct\n");
			test_result = 1;
		}
	}

	if (ibv_destroy_cq(ctx->cq)) {
		fprintf(stderr, "failed to destroy CQ\n");
		test_result = 1;
	}

	if (ibv_dereg_mr(ctx->mr)) {
		fprintf(stderr, "failed to deregister MR\n");
		test_result = 1;
	}

	if (ibv_dealloc_pd(ctx->pd)) {
                fprintf(stderr, "failed to deallocate PD\n");
                test_result = 1;
        }

	if (ctx->use_contig_pages == 0)
                free(ctx->addr);

	free(ctx->qp);

	return test_result;
}

int main(int argc, char *argv[])
{
	int sockfd = 0;
	struct dc_ctx           ctx;
	test_data data;
	int pid = 0, i;

	init_ctx(&ctx, argc, argv);
	if (ctx.processes > 1)
	{
		for(i = 0; i < ctx.processes; i++)
		{
			pid = fork();
			if (pid == 0) // child, then exit the loop
				break;
			
		}
	}
	if (pid == 0)
	{
		init_ib_resources(&ctx);

		sockfd = start_connection(ctx.servername, ctx.port);
		get_data_from_server(sockfd, &data);

		create_ah(&ctx, &data);

		modify_to_rts(&ctx, &data);

		run_traffic(&ctx, &data);

		destroy_resources(&ctx);

		close(sockfd);
	}

	while(wait(NULL) > 0);

	return 0;
}
