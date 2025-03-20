#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <infiniband/verbs.h>
#include "common.h"

int global_active_threads;
int global_free_qp_index;

int init_ib_resources(struct test_ctx *ctx)
{
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
	return 0;
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

	return test_result;
}

int send_data_to_client(int sock, struct test_ctx *ctx, int i)
{

	char msg[MSG_FORMAT_SIZE];
	sprintf(msg, MSG_FORMAT, ctx->qp[i]->qp_num, 0, ctx->portinfo.lid, 0, ctx->mr[i]->rkey, (long long unsigned int)ctx->my_addr[i], 0, ctx->gid_index, ctx->mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send test info\n");
		return 1;
	}

	return 0;
}

int get_data_from_client(int sockfd, test_data *data)
{

	char msg[MSG_FORMAT_SIZE];
	int err = read(sockfd, msg, sizeof(msg));
	int tmp;

        if (err != sizeof(msg)) {
                perror("client read");
                fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
		return 1;
        }

	sscanf(msg, MSG_FORMAT,&data->qp_num, &tmp, &data->lid, &data->psn, &data->rkey, &data->vaddr, &data->srqn, &data->gid_index , &data->mtu);
	return 0;
}

int modify_to_rtr(struct test_ctx *ctx, test_data *remote_data)
{
	int i;

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		struct ibv_qp_attr attr = {
			.qp_state               = IBV_QPS_RTR,
			.path_mtu               = remote_data[i].mtu,
			.dest_qp_num            = remote_data[i].qp_num,
			.rq_psn                 = remote_data[i].psn,
			.max_dest_rd_atomic	= ctx->out_reads,
			.min_rnr_timer          = 12,
			.ah_attr                = {
				.is_global      = 0,
				.dlid           = remote_data[i].lid,
				.sl             = 0,
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
	}
	return 0;
}

int connection_handler(void *ctx)
{
	struct test_ctx l_ctx = *((struct test_ctx*)ctx);
	int sock = *(l_ctx.socket);
	test_data *client_data;
	test_data client_tmp_data;
	int i;

	//get from client how many QPs he wants to open
	get_data_from_client(sock, &client_tmp_data);
	l_ctx.num_of_qps = client_tmp_data.qp_num;
	l_ctx.mtu = client_tmp_data.mtu;

	//create ib resources and init ctx
	ALLOCATE(l_ctx.qp,struct ibv_qp*,l_ctx.num_of_qps);
	ALLOCATE(l_ctx.my_addr,uintptr_t,l_ctx.num_of_qps);
	ALLOCATE(l_ctx.mr,struct ibv_mr*,l_ctx.num_of_qps);
	ALLOCATE(client_data,test_data,l_ctx.num_of_qps);

	if (init_ib_resources(&l_ctx))
	{
		fprintf(stderr,"could not init ib resources\n");
		return 1;
	}
	if (create_qps(&l_ctx))
	{
		fprintf(stderr, "could not create all QPs\n");
	}

	//for each qp, send & get data
	for (i = 0; i < l_ctx.num_of_qps; i++)
	{
		send_data_to_client(sock, &l_ctx, i);
		get_data_from_client(sock, &client_data[i]);
	}

	modify_to_rtr(&l_ctx, client_data);

	//handshake
	send_data_to_client(sock, &l_ctx, 0);
	get_data_from_client(sock, &client_tmp_data);

	//sync, to close resources
	get_data_from_client(sock, &client_tmp_data);

	//destroy all ib resources
	if (destroy_resources(&l_ctx))
	{
		fprintf(stderr, "could not destroy all ib resources\n");
		return 1;
	}

	free(l_ctx.socket);
	free(ctx);

	return 0;
}

int start_connection_manager(struct test_ctx *ctx)
{
	int socket_desc , client_sock , c , *new_sock;
	struct sockaddr_in server , client;

	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		fprintf(stderr,"Could not create socket");
		return 1;
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( ctx->port );

	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		fprintf(stderr,"bind failed. Error\n");
		return 1;
	}

	listen(socket_desc , 150);

	printf("Waiting for incoming connections...\n");

	c = sizeof(struct sockaddr_in);

	while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
	{
		//open new process, and only child process will run this code.
		if (!fork())
		{
			printf("new connection from: %s\n",inet_ntoa(client.sin_addr));
			int err;
			new_sock = malloc(sizeof(client_sock));
			*new_sock = client_sock;
			struct test_ctx *new_ctx;
			ALLOCATE(new_ctx ,struct test_ctx ,1);
			copy_ctx(ctx,new_ctx);
			new_ctx->socket = new_sock;
			err = connection_handler((void*)new_ctx);

			printf("closed connection with: %s\n",inet_ntoa(client.sin_addr));

			// will get here only when the process is dead
			return err;
		}

	}

	if (client_sock < 0)
	{
		perror("accept failed");
		return 1;
	}

	return 0;

}

int main(int argc , char *argv[])
{
        struct test_ctx	ctx;

	init_ctx(&ctx, argc, argv, 1);

	return start_connection_manager(&ctx);
}

