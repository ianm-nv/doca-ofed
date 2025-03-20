#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <infiniband/verbs.h>
#include <pthread.h>
#include "common.h"


int global_active_threads;
int global_free_qp_index;

int create_mr_per_srq(struct test_ctx *ctx) {
	int i;

	ctx->length = 2 * BUFF_SIZE(ctx->size, ctx->page_size) * ctx->num_of_srqs;
	/* create first MR */
	if (create_single_mr(ctx, 0)) {
		fprintf(stderr, "failed to create single mr\n");
		return 1;
	}
	ctx->my_addr[0] = (uintptr_t) ctx->mrs[0]->addr;
	for (i = 1; i < ctx->num_of_srqs; i++) {
//		memset(ctx->mrs[i], 0, sizeof(struct ibv_mr));   // TODO needed?
		ctx->mrs[i] = ctx->mrs[0];
		ctx->my_addr[i] = (uintptr_t) ctx->mrs[0]->addr
				+ i * BUFF_SIZE(ctx->size, ctx->page_size);
	}

	return 0;
}

int pp_post_recv_srq(struct test_ctx *ctx, int srq_num, int counter)
{
    struct ibv_sge sge;
    struct ibv_recv_wr wr, *bad_wr;

    sge.addr = (uintptr_t) ctx->my_addr[srq_num];
    sge.length = ctx->size;
    sge.lkey = ctx->mrs[srq_num]->lkey;
    wr.next       = NULL;
    wr.wr_id      = srq_num;
    wr.sg_list    = &sge;
    wr.num_sge    = 1;

    while (counter--) {
        if (ibv_post_srq_recv(ctx->srqs[srq_num], &wr, &bad_wr)) {
            fprintf(stderr, "Failed to post receive to SRQ\n");
            return 1;
        }
    }
    return 0;
}

int pp_post_recv_all_srqs(struct test_ctx *ctx)
{
    int i;
    for (i = 0; i < ctx->num_of_srqs ; ++i)
    {
        int required_depth_post_recv_srq = (ctx->rx_depth*ctx->num_of_srqs > 8191) ? 8191 : ctx->rx_depth*ctx->num_of_srqs; // TODO check why it's the max
        if (pp_post_recv_srq(ctx, i, required_depth_post_recv_srq))
        {
            fprintf(stderr, "Failed to pp_post_recv_srq. depth required: %d\n", required_depth_post_recv_srq);
            return 1;
        }
    }
    return 0;
}

int init_ib_resources(struct test_ctx *ctx)
{
	int i, cq_size;
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

	if (create_mr_per_srq(ctx))
	{
		fprintf(stderr,"failed to create mr per srq\n");
		return 1;
	}

	cq_size = (ctx->rx_depth*ctx->num_of_srqs*ctx->upper_bound_total_qps > 65408) ? 65408 :
			ctx->rx_depth*ctx->num_of_srqs*ctx->upper_bound_total_qps;
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
		fprintf(stderr, "Couldn't Open the XRC Domain: %d\n", errno);
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

	// srqs initialization (compatible to xrcd).
	struct ibv_srq_init_attr_ex attr;

	memset(&attr, 0, sizeof attr);
	attr.attr.max_wr = (ctx->rx_depth * ctx->upper_bound_total_qps > 8000) ? 8000: ctx->rx_depth * ctx->upper_bound_total_qps;
	attr.attr.max_sge = 30; // unknown limit (for 32 it fails)
	attr.comp_mask = IBV_SRQ_INIT_ATTR_TYPE | IBV_SRQ_INIT_ATTR_XRCD |
			 IBV_SRQ_INIT_ATTR_CQ | IBV_SRQ_INIT_ATTR_PD;
	attr.srq_type = IBV_SRQT_XRC;
	attr.xrcd = ctx->xrcd;
	attr.cq = ctx->cq;
	attr.pd = ctx->pd;

	for(i = 0; i < ctx->num_of_srqs; i++)
	{
		ctx->srqs[i] = ibv_create_srq_ex(ctx->ctx, &attr);
		if (!ctx->srqs[i])  {
			fprintf(stderr, "Couldn't create SRQ\n");
			return 1;
		}
		// fill each srqn in the suitable place in the list.
		ibv_get_srq_num(ctx->srqs[i], &ctx->srq_num_list[i]);
	}
	fprintf(stdout, "%d SRQs were created.\n", ctx->num_of_srqs);

	if (ctx->verb == SEND) {  // TODO support ATOMIC?
		if (pp_post_recv_all_srqs(ctx)) {
            fprintf(stderr, "Couldn't create recv wqes\n");
            return 1;
        }
    }

	if (ibv_query_gid(ctx->ctx, ctx->ib_port, ctx->gid_index, &ctx->gid)) return 1;

	return 0;
}

int destroy_internal_resources(struct test_ctx *ctx)
{
	// this function is per thread. It destroy the resources allocated by the thread (qps, mrs).
	int test_result = 0;
	int i;
	for( i = 0; i < ctx->num_of_qps; i++)
	{
		if (ibv_destroy_qp(ctx->qps[i])) {
			fprintf(stderr, "failed to destroy qps[%d]\n", i);
			test_result = 1;
		}
	}
	return test_result;
}

int destroy_resources(struct test_ctx *ctx)
{
	int test_result = 0;
	int i;

	for (i = 0; i < ctx->num_of_srqs; i++)
	{
		if (ibv_dereg_mr(ctx->mrs[i])) {
			fprintf(stderr, "failed to deregister MR\n");
			test_result = 1;
		}
	}

	for (i = 0; i < ctx->num_of_srqs; i++) {
		if (ibv_destroy_srq(ctx->srqs[i])) {
			fprintf(stderr, "Couldn't destroy SRQ[%d]\n", i);
			test_result = 1;
		}
	}

	if (ctx->xrcd && ibv_close_xrcd(ctx->xrcd)) {
		fprintf(stderr, "Couldn't close the XRC Domain\n");
		test_result = 1;
	}

	if (ibv_destroy_cq(ctx->cq)) {
		fprintf(stderr, "failed to destroy CQ\n");
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

int send_params_per_srq_to_client(int sock, struct test_ctx *ctx, int i)
{
	// send the srq_num, rkey and vaddr (each of them are per srq, because mr is per srq).
	char msg[MSG_SRQ_NUM_FORMAT_SIZE];
	sprintf(msg, MSG_FORMAT_SRQ_NUMBER, ctx->srq_num_list[i], ctx->mrs[i]->rkey, (uint64_t)ctx->my_addr[i]);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send test info\n");
		return 1;
	}

	return 0;
}


int send_data_to_client(int sock, struct test_ctx *ctx, int i)
{

	char msg[MSG_FORMAT_SIZE];

	sprintf(msg, MSG_FORMAT, ctx->qps[i]->qp_num, 0, ctx->portinfo.lid,
		(uint64_t)ctx->gid.global.subnet_prefix, (uint64_t)ctx->gid.global.interface_id,
		0, ctx->num_of_srqs, ctx->gid_index, ctx->mtu);
	if (write(sock, msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Couldn't send test info\n");
		return 1;
	}

	return 0;
}

int get_data_from_client(int sockfd, test_data *data)
{
	char msg[MSG_FORMAT_SIZE];
	uint64_t subnet_prefix = 0, interface_id = 0;
	int err = read(sockfd, msg, sizeof(msg));
	int tmp;

        if (err != sizeof(msg)) {
                perror("client read");
                fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
		return 1;
        }
	sscanf(msg, MSG_FORMAT,&data->qp_num, &tmp, &data->lid,
		&subnet_prefix, &interface_id,
		&data->psn, &data->srqn, &data->gid_index , &data->mtu);

	data->gid.global.subnet_prefix = subnet_prefix;
	data->gid.global.interface_id = interface_id;
	return 0;
}

int modify_to_rtr(struct test_ctx *ctx, test_data *remote_data)
{
	int i;
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		struct ibv_qp_attr attr = {
			.qp_state               = IBV_QPS_RTR,
			.dest_qp_num            = remote_data[i].qp_num,
			.path_mtu               = ctx->mtu,
			.rq_psn                 = remote_data[i].psn,
			.min_rnr_timer          = 12,
			.max_dest_rd_atomic	= ctx->out_reads,
			.ah_attr                = {
				.dlid           = remote_data[i].lid,
				.sl             = ctx->sl,
				.port_num       = ctx->ib_port,
				.is_global      = 1,
				.grh.hop_limit  = 5,
				.grh.dgid = remote_data[i].gid,
				.grh.sgid_index = remote_data[i].gid_index,
				.src_path_bits  = 0,
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
			fprintf(stderr, "Failed to modify QP to RTR, errno: %d\n", errno);
			return 1;
		}
	}

	return 0;
}

int create_recv_qps(struct test_ctx *ctx) {
    struct ibv_qp_init_attr_ex init;
    struct ibv_qp_attr mod;
    int i;

    for (i = 0; i < ctx->num_of_qps; i++) {
        /* Create QP */
        memset(&init, 0, sizeof init);
        init.qp_type = IBV_QPT_XRC_RECV;
        init.comp_mask = IBV_QP_INIT_ATTR_XRCD;
        init.xrcd = ctx->xrcd;

        ctx->qps[i] = ibv_create_qp_ex(ctx->ctx, &init);
        if (!ctx->qps[i]) {
            fprintf(stderr, "Couldn't create recv QP[%d] errno %d\n", i, errno);
            return 1;
        }

        /* Modify QP to INIT state */
        mod.qp_state = IBV_QPS_INIT;
        mod.pkey_index = 0;
        mod.port_num = ctx->ib_port;
        mod.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE
        | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC;

        if (ibv_modify_qp(ctx->qps[i], &mod,
            IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT
            | IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify recv QP[%d] to INIT\n", i);
        return 1;
            }
    }
    fprintf(stdout, "Thread %ld:    %d RECV QPs were created.\n", pthread_self(), ctx->num_of_qps);

    return 0;
}

void* connection_handler(void *ctx)
{
    int* ret=malloc(sizeof(int)); *ret = 0;
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
	ALLOCATE(l_ctx.qps,struct ibv_qp*,l_ctx.num_of_qps);
	ALLOCATE(client_data,test_data,l_ctx.num_of_qps);

	if (create_recv_qps(&l_ctx))
	{
		fprintf(stderr, "could not create all recv QPs\n");
		*ret = 1 ; return (void*)ret;
	}

	//for each qp, send & get data
	for (i = 0; i < l_ctx.num_of_qps; i++)
	{
		send_data_to_client(sock, &l_ctx, i);
		get_data_from_client(sock, &client_data[i]);
	}

	fprintf(stdout, "Thread %ld:    sending %d srq numbers to the client\n", pthread_self(), l_ctx.num_of_srqs);
	for (i = 0; i < l_ctx.num_of_srqs; i++)
	{
		send_params_per_srq_to_client(sock, &l_ctx, i);
	}

	modify_to_rtr(&l_ctx, client_data);

	//handshake
	send_data_to_client(sock, &l_ctx, 0);
	get_data_from_client(sock, &client_tmp_data);

	//sync, to close resources
	get_data_from_client(sock, &client_tmp_data);

	//destroy all ib resources
	if (destroy_internal_resources(&l_ctx))
	{
		fprintf(stderr, "could not destroy all ib resources\n");
        *ret = 1 ; return (void*)ret;
	}

	free(l_ctx.socket);
	free(ctx);
	printf("Thread %ld:    closed connection with client %d.\n", pthread_self(), *l_ctx.socket);

    return (void*)ret;
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
		// open new thread for the child. (New process won't work because it can't work with ctx & pd created in the old process)
    	pthread_t sniffer_thread;
    	new_sock = malloc(sizeof(client_sock));
		*new_sock = client_sock;
		printf("New connection from client IP: %s, listen_port: %d, port: %d\n", inet_ntoa(client.sin_addr), ctx->port, ntohs(client.sin_port));

		struct test_ctx *new_ctx;
		ALLOCATE(new_ctx ,struct test_ctx ,1);
		copy_ctx(ctx,new_ctx);
		new_ctx->socket = new_sock;

        // create new thread
		if (pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_ctx) < 0)
        {
            perror("could not create thread");
            exit(1);
        }
	}

	if (client_sock < 0)
	{
		perror("accept failed");
		return 1;
	}

	if (destroy_resources(ctx))
	{
		fprintf(stderr, "could not destroy all ib resources\n");
		return 1;
	}
	fprintf(stdout, "END TEST SERVER. destroy_resources is done.\n");
	return 0;

}

int init_srqs_memory(struct test_ctx *ctx)
{
	// allocate memory for the list of srq_nums got from server
	ALLOCATE(ctx->srq_num_list,uint32_t,ctx->num_of_srqs);
	// allocate memory for the list of srqs
	ALLOCATE(ctx->srqs,struct ibv_srq*,ctx->num_of_srqs);
	ALLOCATE(ctx->mrs,struct ibv_mr*,ctx->num_of_srqs);
	ALLOCATE(ctx->my_addr,uintptr_t,ctx->num_of_srqs);
	return 0;
}

void* connection_handler_post_recv_srq(void *ctx)
{
    int* ret=malloc(sizeof(int)); *ret = 0;
	struct test_ctx l_ctx = *((struct test_ctx*)ctx);
	struct ibv_wc wc;
	fprintf(stdout, "SRQ Thread %ld:    created post recv thread.\n", pthread_self());

	while (1) {  // post recv thread would only end when server will shut down.
		int poll_result;
		poll_result = ibv_poll_cq(l_ctx.cq, 1, &wc);
		if (poll_result < 0) {
			fprintf(stderr, "SRQ Thread.  Couldn't poll cq");
			*ret=1 ; return (void*)ret;
		}
		else if (poll_result == 0) continue; // ibv_poll_cq is 0 means cq is empty. try to poll cq again.
		else { // poll_result > 0 (= poll succeeded).
			if (pp_post_recv_srq(ctx, wc.wr_id, 1)) {
				fprintf(stderr, "SRQ Thread.  Couldn't post recv srq. srq_num: %ld\n", wc.wr_id);
                *ret=1 ; return (void*)ret;
            }
		}
	}
}

int init_post_recv_thread(struct test_ctx *ctx)
{
	if (ctx->verb == SEND)
	{
		pthread_t post_recv_srq_thread;
		struct test_ctx *new_ctx_srq;
		ALLOCATE(new_ctx_srq ,struct test_ctx ,1);
		copy_ctx(ctx,new_ctx_srq);
		if (pthread_create( &post_recv_srq_thread, NULL ,  connection_handler_post_recv_srq , (void*) new_ctx_srq) < 0)
		{
			perror("could not create thread");
			exit(1);
		}
	}
	return 0;
}

int main(int argc , char *argv[])
{
	struct test_ctx	ctx;

	init_ctx(&ctx, argc, argv, 1);
	init_srqs_memory(&ctx);
    // init all the ib resources & the srqs
	if (init_ib_resources(&ctx)) {
        fprintf(stderr, "Failed to create IB xrc & srq resources.\n");
        return 1;
    }
	init_post_recv_thread(&ctx);
	return start_connection_manager(&ctx);
}

