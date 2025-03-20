#define _GNU_SOURCE
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<pthread.h>
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include "common.h"

int global_active_threads;

void *connection_handler(void *);

int init_ib_resources(struct test_ctx *ctx)
{
	struct ibv_exp_device_attr dattr;

        ctx->dev_list = ibv_get_device_list(NULL);
        if (!ctx->dev_list) {
                perror("Failed to get IB devices list");
                return -1;
        }

        if (!ctx->ib_devname) {
                ctx->ib_dev = *ctx->dev_list;
                if (!ctx->ib_dev) {
                        fprintf(stderr, "No IB devices found\n");
                        return -1;
                }
        } else {
                int i;
                for (i = 0; ctx->dev_list[i]; ++i)
                        if (!strcmp(ibv_get_device_name(ctx->dev_list[i]), ctx->ib_devname))
                                break;
                ctx->ib_dev = ctx->dev_list[i];
                if (!ctx->ib_dev) {
                        fprintf(stderr, "IB device %s not found\n", ctx->ib_devname);
                        return -1;
                }
        }

        ctx->ctx = ibv_open_device(ctx->ib_dev);
        if (!ctx->ctx) {
                fprintf(stderr, "Couldn't get context for %s\n",
                        ibv_get_device_name(ctx->ib_dev));
                return -1;
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

        ctx->cq = ibv_create_cq(ctx->ctx, ctx->rx_depth*ctx->num_of_qps, NULL, NULL, 0);
        if (!ctx->cq) {
                fprintf(stderr, "failed to create cq\n");
                return -1;
        }

        if (ibv_query_port(ctx->ctx, ctx->ib_port, &ctx->portinfo)) {
                fprintf(stderr, "Couldn't get port info\n");
                return 1;
        }
	return 1;
}

void send_data_to_client(int sock, test_data data)
{

	char msg[MSG_FORMAT_SIZE];
	sprintf(msg, MSG_FORMAT, data.qp_num, 0, data.lid, data.psn, data.rkey, data.vaddr, data.srqn, data.gid_index, data.mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send local address\n");
	}
}

void get_data_from_client(int sockfd, test_data *data)
{

	char msg[MSG_FORMAT_SIZE];
	int err = read(sockfd, msg, sizeof(msg));
	int tmp;

        if (err != sizeof(msg)) {
                perror("client read");
                fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
        }

	sscanf(msg, MSG_FORMAT,&data->qp_num, &tmp, &data->lid, &data->psn, &data->rkey, &data->vaddr, &data->srqn, &data->gid_index , &data->mtu);

}

int modify_to_rtr(handler_data *l_data, test_data *remote_data)
{
       struct ibv_qp_attr attr = {
                .qp_state               = IBV_QPS_RTR,
                .path_mtu               = remote_data->mtu,
                .dest_qp_num            = remote_data->qp_num,
                .rq_psn                 = remote_data->psn,
		.max_dest_rd_atomic= 1,
                .min_rnr_timer          = 12,
                .ah_attr                = {
                        .is_global      = 0,
                        .dlid           = remote_data->lid,
                        .sl             = 0,
                        .src_path_bits  = 0,
                        .port_num       = l_data->ib_port
                }
        };
        if (ibv_modify_qp(l_data->data.qp, &attr,
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
}

void *connection_handler(void *h_data)
{
	handler_data l_data = *((handler_data*)h_data);
	int sock = *(l_data.socket);
	test_data client_data;

	send_data_to_client(sock, l_data.data);
	get_data_from_client(sock, &client_data);
	//print_test_data(&l_data.data);
	//print_test_data(&client_data);

	modify_to_rtr(&l_data, &client_data);

	//sync, to close resources
	get_data_from_client(sock, &client_data);

	free(l_data.socket);
	free(h_data);
	global_active_threads--;

	return 0;
}

int start_connection_manager(struct test_ctx *ctx, test_data *data)
{
	int socket_desc , client_sock , c , *new_sock;
	struct sockaddr_in server , client;
	int current_thread = 0;

	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( ctx->port );

	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		perror("bind failed. Error");
		return -1;
	}

	listen(socket_desc , 150);

	puts("Waiting for incoming connections...");
	c = sizeof(struct sockaddr_in);

	global_active_threads = ctx->num_of_qps;

	while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
	{
		pthread_t sniffer_thread;
		new_sock = malloc(sizeof(client_sock));
		*new_sock = client_sock;

		//init handler data
		handler_data *h_data = malloc(sizeof(handler_data));
		copy_test_data(&data[current_thread%ctx->num_of_qps], &h_data->data);
		h_data->socket = new_sock;
		h_data->tcp_port = ctx->port;
		h_data->ib_port = ctx->ib_port;

		if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) h_data) < 0)
		{
			perror("could not create thread");
			return -1;
		}
		if(++current_thread == ctx->num_of_qps)
		{
			while(global_active_threads > 0);
			return 0;
		}

	}
	 
	if (client_sock < 0)
	{
		perror("accept failed");
		return -1;
	}
	 
	return 1;

}

int destroy_resources(struct test_ctx *ctx)
{
	int test_result = 0;
	int i;

	for( i = 0; i < ctx->num_of_qps; i++)
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

	return test_result;
}


int main(int argc , char *argv[])
{
        struct test_ctx	ctx;
	test_data *data;
	int i, ret;

	init_ctx(&ctx, argc, argv);

	ALLOCATE(data ,test_data ,ctx.num_of_qps);

	init_ib_resources(&ctx);

	create_qps(&ctx);

	init_test_data(&ctx,data);

	ret = start_connection_manager(&ctx, data);

	destroy_resources(&ctx);
}

