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

void *connection_handler(void *);

int init_ib_resources(struct dc_ctx *ctx)
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

	struct ibv_srq_init_attr attr = {
		.attr = {
			.max_wr  = ctx->rx_depth,
			.max_sge = 1
		}
	};

	ctx->srq = ibv_create_srq(ctx->pd, &attr);
	if (!ctx->srq)  {
		fprintf(stderr, "Couldn't create SRQ\n");
		return -1;
	}

	ibv_get_srq_num(ctx->srq, &ctx->srqn);

        if (ibv_query_port(ctx->ctx, ctx->ib_port, &ctx->portinfo)) {
                fprintf(stderr, "Couldn't get port info\n");
                return 1;
        }
	return 1;
}

int create_dct(struct dc_ctx *ctx)
{
	struct ibv_exp_dct_init_attr dctattr = {
		.pd = ctx->pd,
		.cq = ctx->cq,
		.srq = ctx->srq,
		.dc_key = ctx->dct_key,
		.port = ctx->ib_port,
		.access_flags = IBV_ACCESS_REMOTE_READ,
		.min_rnr_timer = 2,
		.tclass = 0,
		.flow_label = 0,
		.mtu = ctx->mtu,
		.pkey_index = 0,
		.gid_index = 0,
		.hop_limit = 1,
		.create_flags = 0,
		.inline_size = ctx->inl,
	};

	ctx->dct = ibv_exp_create_dct(ctx->ctx, &dctattr);
	if (!ctx->dct) {
		printf("create dct failed\n");
		return -1;
	}
	return 1;
}

void send_data_to_client(int sock, test_data data)
{

	char msg[MSG_FORMAT_SIZE];
	sprintf(msg, MSG_FORMAT, data.dct_num, data.dct_key, data.lid, data.psn, data.rkey, data.vaddr, data.srqn, data.gid_index, data.mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send local address\n");
	}
}

void *connection_handler(void *h_data)
{
	handler_data l_data = *((handler_data*)h_data);
	int sock = *(l_data.socket);

	send_data_to_client(sock, l_data.data);
	free(l_data.socket);
	free(h_data);
	return 0;
}

int start_connection_manager(int port, test_data *data)
{
	int socket_desc , client_sock , c , *new_sock;
	struct sockaddr_in server , client;

	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( port );

	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		perror("bind failed. Error");
		return -1;
	}

	listen(socket_desc , 150);

	puts("Waiting for incoming connections...");
	c = sizeof(struct sockaddr_in);

	while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
	{
		pthread_t sniffer_thread;
		new_sock = malloc(sizeof(client_sock));
		*new_sock = client_sock;

		//init handler data
		handler_data *h_data = malloc(sizeof(handler_data));
		copy_test_data(data, &h_data->data);
		h_data->socket = new_sock;
		h_data->tcp_port = port;

		if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) h_data) < 0)
		{
			perror("could not create thread");
			return -1;
		}

	}
	 
	if (client_sock < 0)
	{
		perror("accept failed");
		return -1;
	}
	 
	return 1;

}

int main(int argc , char *argv[])
{
        struct dc_ctx	ctx;
	test_data	data;

	init_ctx(&ctx, argc, argv);

	init_ib_resources(&ctx);

	create_dct(&ctx);

	init_test_data(&ctx,&data);

	start_connection_manager(ctx.port, &data);
}
