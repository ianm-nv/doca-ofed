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
#include <sys/wait.h>

struct test_ctx *global_ctx;

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

        ctx->cq = ibv_create_cq(ctx->ctx, ctx->tx_depth*ctx->num_of_qps, NULL, NULL, 0);
        if (!ctx->cq) {
                fprintf(stderr, "failed to create cq\n");
                return -1;
        }


	if(create_qps(ctx))
	{
		fprintf(stderr,"failed to create qps\n");
		return 1;
	}

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
	sprintf(msg, MSG_FORMAT, ctx->qp[i]->qp_num, 0, ctx->portinfo.lid, 0, ctx->mr[i]->rkey, (long long unsigned int)ctx->my_addr[i], 0, ctx->gid_index, ctx->mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send local address\n");
		exit(1);
	}
	return 0;
}

int send_info_to_server(int sock, struct test_ctx *ctx)
{
	char msg[MSG_FORMAT_SIZE];
	sprintf(msg, MSG_FORMAT, ctx->num_of_qps, 0, 0, 0, 0, (long long unsigned int)0, 0, 0, ctx->mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send info to server\n");
		exit(1);
	}
	return 0;
}

int get_data_from_server(int sockfd, test_data *data)
{
	char msg[MSG_FORMAT_SIZE];

	int err = read(sockfd, msg, sizeof(msg));
	int tmp;

        if (err != sizeof(msg)) {
                perror("client read");
                fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
		exit(1);
        }

	sscanf(msg, MSG_FORMAT,&data->qp_num, &tmp, &data->lid, &data->psn, &data->rkey, &data->vaddr, &data->srqn, &data->gid_index , &data->mtu);
	return 0;

}

int modify_to_rts(struct test_ctx *ctx, test_data *data)
{
	int i;
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		struct ibv_qp_attr attr = {
			.qp_state               = IBV_QPS_RTR,
			.path_mtu               = ctx->mtu,
			.dest_qp_num            = data[i].qp_num,
			.rq_psn                 = data[i].psn,
			.max_dest_rd_atomic     = ctx->out_reads,
			.min_rnr_timer          = 12,
			.ah_attr                = {
				.is_global      = 0,
				.dlid           = data[i].lid,
				.sl             = ctx->sl,
				.src_path_bits  = 0,
				.port_num       = ctx->ib_port
			}
		};

		if (ibv_modify_qp(ctx->qp[i], &attr,
				  IBV_QP_STATE              |
				  IBV_QP_AV                 |
				  IBV_QP_PATH_MTU           |
				  IBV_QP_DEST_QPN           |
				  IBV_QP_RQ_PSN             |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER)) {
			fprintf(stderr, "Failed to modify QP to RTR\n");
			return 1;
		}
		attr.qp_state       = IBV_QPS_RTS;
		attr.timeout        = ctx->qp_timeout;
		attr.retry_cnt      = 7;
		attr.rnr_retry      = 7;
		attr.sq_psn         = 0;
		attr.max_rd_atomic  = ctx->out_reads;
		if (ibv_modify_qp(ctx->qp[i], &attr,
				  IBV_QP_STATE              |
				  IBV_QP_TIMEOUT            |
				  IBV_QP_RETRY_CNT          |
				  IBV_QP_RNR_RETRY          |
				  IBV_QP_SQ_PSN             |
				  IBV_QP_MAX_QP_RD_ATOMIC)) {
			fprintf(stderr, "Failed to modify QP to RTS\n");
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


int run_traffic(struct test_ctx *ctx, test_data *data)
{
	uint64_t totscnt = 0;
	uint64_t totccnt = 0;
	uint64_t *scnt;
	uint64_t *ccnt;
	struct ibv_send_wr *wr;
	struct ibv_send_wr *bad_wr;
	struct ibv_sge  *sg_list;
	int err;
	int i;
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

	for (i = 0; i < ctx->num_of_qps; i++)
	{
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

			wr[i].wr.atomic.remote_addr = data[i].vaddr;
			wr[i].wr.atomic.rkey = data[i].rkey;

		}
	        else if(ctx->verb == READ)
			wr[i].opcode = IBV_WR_RDMA_READ;

		wr[i].send_flags = IBV_SEND_SIGNALED;
		sg_list[i].addr = ctx->my_addr[i];
		sg_list[i].length = ctx->size;
		sg_list[i].lkey = ctx->mr[i]->lkey;
		wr[i].sg_list = &sg_list[i];
		wr[i].wr.rdma.remote_addr = data[i].vaddr;
		wr[i].wr.rdma.rkey = data[i].rkey;
		wr[i].wr_id = i;

		if (ctx->size <= ctx->inl)
			wr[i].send_flags |= IBV_SEND_INLINE;
	}

	while (global_ctx->state != END_STATE)
	{
		int qp_index;
		for(qp_index = 0; qp_index < ctx->num_of_qps; qp_index++)
		{
			while ( (scnt[qp_index] - ccnt[qp_index]) < ctx->tx_depth )
			{
				if (scnt[qp_index] % ctx->cq_mod == 0 && ctx->cq_mod > 1)
					wr[qp_index].send_flags &= ~IBV_SEND_SIGNALED;
				err = ibv_post_send(ctx->qp[qp_index], &wr[qp_index], &bad_wr);
				if (err) {
					fprintf(stderr, "failed to post send request #%ld\n",ctx->iters + i);
					return -1;
				}

				totscnt += 1;
				scnt[qp_index] += 1;

				if (ctx->size <= (ctx->page_size / 2)) {
					if (ctx->do_random_addr)
					{
						increase_rand_loc_addr(wr[qp_index].sg_list,ctx->size,scnt[qp_index],ctx->my_addr[qp_index],0,ctx->cache_line_size,ctx->page_size, rand());
						increase_rand_rem_addr(&wr[qp_index],ctx->size,scnt[qp_index],data[qp_index].vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size, rand());
					}
					else
					{
						increase_loc_addr(wr[qp_index].sg_list,ctx->size,scnt[qp_index],ctx->my_addr[qp_index],0,ctx->cache_line_size,ctx->page_size);
						increase_rem_addr(&wr[qp_index],ctx->size,scnt[qp_index],data[qp_index].vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size);
					}
				}

				if (scnt[qp_index]%ctx->cq_mod == (ctx->cq_mod - 1))
				 	wr[qp_index].send_flags |= IBV_SEND_SIGNALED;
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

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		if (ibv_destroy_qp(ctx->qp[i]))
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
		if (ibv_dereg_mr(ctx->mr[i])) {
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

	free(ctx->qp);

	return test_result;
}


int main(int argc, char *argv[])
{
	int sockfd = 0;
	struct test_ctx           ctx;
	test_data *data;
	test_data tmp_data;
	int pid = 0, i;

	init_ctx(&ctx, argc, argv, 1);
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

		if (modify_to_rts(&ctx, data))
		{
			fprintf(stderr, "could not modify QP to RTS\n");
			return 1;
		}

		//handshake
		get_data_from_server(sockfd, &tmp_data);
		send_data_to_server(sockfd, &ctx, 0);

		if (run_traffic(&ctx, data))
		{
			fprintf(stderr,"could not finish traffic\n");
			return 1;
		}

		//sync, to let the server know I am done
		send_info_to_server(sockfd, &ctx);
		if (destroy_resources(&ctx))
		{
			fprintf(stderr, "could not destroy all ib resources\n");
			return 1;
		}

		close(sockfd);
	}

	while (wait(NULL) > 0);

	return 0;
}
