#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#include <sys/types.h>
#include "common.h"

void *connection_handler(void *);

struct test_ctx *global_ctx;
pthread_t sniffer_thread;

static void sig_catcher(int signo) {
    // TODO: add killing QP

    /* TODO: clean all ib resources.. */
    exit(1);
}

int create_recv_wqes(struct test_ctx *ctx)
{
    struct ibv_recv_wr      *bad_wr_recv;
    int 			j;

    ctx->recv_sge_list.addr  = (uintptr_t)ctx->addr;
    ctx->recv_sge_list.length = ctx->size;
    ctx->recv_sge_list.lkey   = ctx->mr->lkey;

    ctx->rwr.sg_list	= &ctx->recv_sge_list;
    ctx->rwr.wr_id		= 0;
    ctx->rwr.next		= NULL;
    ctx->rwr.num_sge	= 1;

    ctx->rx_buffer_addr = ctx->recv_sge_list.addr;

    for (j = 0; j < ctx->rx_depth ; ++j) {

        if (ibv_post_srq_recv(ctx->srq, &ctx->rwr, &bad_wr_recv)) {
            fprintf(stderr, "Couldn't post recv SRQ");
            return 1;
        }

        if (ctx->size <= (ctx->page_size / 2)) {
            increase_loc_addr(&ctx->recv_sge_list,
                              ctx->size,
                              j,
                              ctx->rx_buffer_addr,
                              0,
                              ctx->cache_line_size,
                              ctx->page_size);
        }
    }

    ctx->recv_sge_list.addr = ctx->rx_buffer_addr;

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
        int i; for (i = 0; ctx->dev_list[i]; ++i) {
            if (strcmp(ibv_get_device_name(ctx->dev_list[i]), ctx->ib_devname)) continue;
            ctx->ib_dev = ctx->dev_list[i];
        }
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
    if (ctx->device_name_by_id == DEVICE_ERROR) {
        fprintf(stderr, "Couldn't get device name\n");
        return 1;
    }

    /* TODO: do query device instead of this */
    switch (ctx->device_name_by_id)
    {
        case CONNECTIB:
        case CONNECTX4:
        case CONNECTX4LX:
        case CONNECTX5:
        case CONNECTX5EX:
        case CONNECTX6:
        case CONNECTX6DX:
        case MLX5GENVF:
        case CONNECTX6LX:
	case BLUEFIELD3:
            break;
        default:
            fprintf(stderr, "DC transport is not suppported for this device\n");
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

    ctx->cq = ibv_create_cq(ctx->ctx, ctx->rx_depth*ctx->num_of_qps, NULL, NULL, 0);
    if (!ctx->cq) {
        fprintf(stderr, "failed to create cq\n");
        return 1;
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
        return 1;
    }

    ibv_get_srq_num(ctx->srq, &ctx->srqn);

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

    if (ctx->verb == SEND) {
        if (create_recv_wqes(ctx)) {
            fprintf(stderr, "Couldn't create recv wqes\n");
            return 1;
        }
    }
    if (ibv_query_gid(ctx->ctx, ctx->ib_port, ctx->gid_index, &ctx->gid)) return 1;

    return 0;
}

int create_dct_qp(struct test_ctx *ctx, int index)
{
    struct ibv_qp_init_attr_ex attr;
    struct mlx5dv_qp_init_attr attr_dv;
    enum ibv_wr_opcode opcode;
    memset(&attr, 0, sizeof(struct ibv_qp_init_attr_ex));
    memset(&attr_dv, 0, sizeof(attr_dv));

    attr.pd = ctx->pd;
    attr.send_cq = ctx->cq;
    attr.recv_cq = ctx->cq;
    attr.srq = ctx->srq;
    attr.cap.max_inline_data = ctx->inl;
    attr.qp_type = IBV_QPT_DRIVER;
    attr.comp_mask |= IBV_QP_INIT_ATTR_PD;

    opcode = opcode_verbs_array[ctx->verb];
    if(0);
    else if (opcode == IBV_WR_SEND)
        attr.send_ops_flags |= IBV_QP_EX_WITH_SEND;
    else if (opcode == IBV_WR_RDMA_WRITE)
        attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE;
    else if (opcode == IBV_WR_RDMA_READ)
        attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_READ;

    attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCT;
    attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
    attr_dv.dc_init_attr.dct_access_key = ctx->dct_key;
    attr.comp_mask &= ~IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;

    ctx->qp[index] = mlx5dv_create_qp(ctx->ctx, &attr, &attr_dv);
    if (ctx->qp[index] == NULL) {
        fprintf(stderr, "Unable to create DCT QP.\n");
        return 1;
    }
    ctx->qpx[index] = ibv_qp_to_qp_ex(ctx->qp[index]);
    ctx->dv_qp[index] = mlx5dv_qp_ex_from_ibv_qp_ex(ctx->qpx[index]);
    return 0;
}

int modify_dct_qp_to_init(struct test_ctx *ctx, int index)
{
    struct ibv_qp_attr attr;
    int ret;
    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    memset(&attr, 0, sizeof(struct ibv_qp_attr));
    attr.qp_state        = IBV_QPS_INIT;
    attr.pkey_index      = 0;
    attr.port_num = ctx->ib_port;

    switch (ctx->verb) {
        case READ  : attr.qp_access_flags = IBV_ACCESS_REMOTE_READ;  break;
        case WRITE : attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE; break;
        case SEND  : attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE;
    }
    ret = ibv_modify_qp(ctx->qp[index], &attr, flags);

    if (ret) {
        fprintf(stderr, "Failed to modify DCT QP to INIT, ret=%d\n", ret);
        return 1;
    }
    return 0;
}

int modify_dct_qp_to_rtr(struct ibv_qp *qp, struct test_ctx *ctx, int index)
{
    struct ibv_qp_attr attr;
    int flags = IBV_QP_AV |
                IBV_QP_PATH_MTU |
                IBV_QP_MIN_RNR_TIMER |
                IBV_QP_STATE;

    memset(&attr, 0, sizeof(struct ibv_qp_attr));
    attr.qp_state        = IBV_QPS_RTR;
    attr.min_rnr_timer = 12;
    attr.path_mtu = ctx->mtu;
    attr.ah_attr.is_global  = 1;

    attr.ah_attr.grh.sgid_index = ctx->gid_index;
    attr.ah_attr.port_num = ctx->ib_port;
    attr.ah_attr.src_path_bits = 0;

    if (ibv_modify_qp(qp, &attr, flags)) {
        fprintf(stderr, "Failed to modify QP to RTR\n");
        return 1;
    }
    return 0;
}

void send_data_to_client(int sock, test_data data)
{
    char msg[MSG_FORMAT_SIZE];
    // due to those values are __be64, not uint64_t
    uint64_t subnet_prefix = data.gid.global.subnet_prefix;
    uint64_t interface_id = data.gid.global.interface_id;

    sprintf(msg, MSG_FORMAT, data.dct_num, data.dct_key, data.lid,
            subnet_prefix, interface_id, data.psn, data.rkey,
            data.vaddr, data.srqn, data.gid_index, data.mtu);

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

//int start_connection_manager(int port, test_data *data)
void *start_connection_manager(void *h_data)
{
    int port = ((handler_data*)h_data)->tcp_port;

    test_data *data = &((handler_data*)h_data)->data;
    char *logname = ((handler_data*)h_data)->logname;

    int socket_desc , client_sock , c , *new_sock;
    struct sockaddr_in server , client;

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket\n");
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( port );
    if (bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        exit(1);
    }

    listen(socket_desc , 150);

    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);

    while ((client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)))
    {
        pthread_t sniffer_thread;
        new_sock = malloc(sizeof(client_sock));
        *new_sock = client_sock;

        printf("New connection from client IP: %s, listen_port: %d, port: %d\n", inet_ntoa(client.sin_addr), port, ntohs(client.sin_port));

        FILE* file;
        if (logname) {
        	file = fopen(logname, "a"); // write to the end of the file.
        	fprintf(file, "New connection from client IP: %s, listen_port: %d, port: %d\n", inet_ntoa(client.sin_addr), port, ntohs(client.sin_port));
        	fclose(file);
        }

        //init handler data
        handler_data *h_data = malloc(sizeof(handler_data));
        copy_test_data(data, &h_data->data);
        h_data->socket = new_sock;
        h_data->tcp_port = port;

        if (pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) h_data) < 0)
        {
            perror("could not create thread");
            exit(1);
        }
    }
    if (client_sock < 0)
    {
        perror("accept failed");
        exit(1);
    }

    return NULL;
}

void poll_cq(struct test_ctx *ctx, test_data *data)
{
    struct ibv_wc           *wc          = NULL;
    struct ibv_recv_wr      *bad_wr_recv = NULL;
    int			poll_batch   = 16;
    int			ne, i;
    int			rcnt = 0;

    ALLOCATE(wc, struct ibv_wc, poll_batch);

    while (1)
    {
        ne = ibv_poll_cq(ctx->cq, poll_batch, wc);

        if (ne > 0)
        {
            for(i = 0; i < ne; i++)
            {
                if (wc[i].status != IBV_WC_SUCCESS)
                {
                    fprintf(stderr, "got CQE with error.. exiting\n");
                    exit(1);
                }

                if (ibv_post_srq_recv(ctx->srq, &ctx->rwr, &bad_wr_recv))
                {
                    fprintf(stderr, "failed to post_srq_recv\n");
                    exit(1);
                }
                rcnt++;
                if (ctx->size <= (ctx->page_size / 2))
                    increase_loc_addr(ctx->rwr.sg_list, ctx->size, rcnt, ctx->rx_buffer_addr, 0, ctx->cache_line_size, ctx->page_size);
            }
        }
        else if (ne < 0)
        {
            fprintf(stderr, "error in poll cq\n");
            exit(1);
        }
    }
}

int init_connection_manager_thread(struct test_ctx *ctx, test_data *data, handler_data *h_data)
{
    //init handler data
    copy_test_data(data, &h_data->data);
    h_data->tcp_port = ctx->port;

    if (pthread_create( &sniffer_thread, NULL, start_connection_manager, (void*) h_data) < 0)
    {
        perror("could not create thread");
        return -1;
    }

    return 0;
}

void force_sig_catcher_on_parent(sigset_t *set)
{
    /* disable signal catcher on child threads */
    sigemptyset(set);
    sigaddset (set, SIGINT);
    pthread_sigmask(SIG_SETMASK, set, NULL);
}

void init_sig_catcher(struct test_ctx *ctx)
{
    global_ctx = ctx;
    if (signal(SIGINT, sig_catcher) == SIG_ERR) {
        printf("failed to init signal handler\n");
        exit(1);
    }
}

char* create_logname_server(char* file_path, char* port_str) {
	char* name = "/dc_server_logfile_port_";
	char *result = malloc(strlen(file_path) + strlen(name) + strlen(port_str)+1);//+1 for the null-terminator
	strcpy(result, file_path);
	strcat(result, name);
	strcat(result, port_str);
	return result;
}

int main(int argc , char *argv[])
{
    struct test_ctx	ctx;
    test_data	data;
    sigset_t set;
    handler_data h_data;

    ibv_fork_init();

    init_ctx(&ctx, argc, argv, 0);
    char **ports_array = (char**)malloc((ctx.n_ports+1)*sizeof(*ports_array));
    if (parse_port_list(&ctx, &ports_array)){
        destroy_arrays(NULL, ports_array);
        exit(1);
    }

    if (1<ctx.n_ports) {
        fprintf(stderr, "Error, server only supports a single listen port (currently)\n");
        exit(1);
    }

    FILE* file;
    if (NULL == ctx.file_path) {
    	h_data.logname = NULL;
    } else { // there is a logfile
    	h_data.logname = create_logname_server(ctx.file_path, ctx.port_str);
    	printf("logname: %s\n", h_data.logname);
    	file = fopen(h_data.logname, "w");
		if (NULL == file) {
			fprintf(stderr, "Error opening file! Please check the file_path you gave (-F)\n");
			exit(1);
		}
    }

    print_command(h_data.logname, argc, argv);

    init_sig_catcher(&ctx);

    if (init_ib_resources(&ctx)) {
        fprintf(stderr, "Failed to create IB resources: %m\n");
        return 1;
    }

    if (create_dct_qp(&ctx, 0)) {
        fprintf(stderr, "Failed to create DCT QP: %m\n");
        exit(1);
    }

    if (modify_dct_qp_to_init(&ctx, 0)) {
        fprintf(stderr, "Failed to modify DCT QP to INIT: %m\n");
        exit(1);
    }

    if (modify_dct_qp_to_rtr(ctx.qp[0], &ctx, 0)) {
        fprintf(stderr, "Failed to modify DCT QP to RTR: %m\n");
        exit(1);
    }
    ctx.dct_num = ctx.qp[0]->qp_num;

    init_test_data(&ctx, &data);

    if (init_connection_manager_thread(&ctx, &data, &h_data) == -1) return 1;  // FAIL

    force_sig_catcher_on_parent(&set);

    if (ctx.verb == SEND)
        poll_cq(&ctx, &data);

    pthread_join(sniffer_thread, NULL);
    destroy_arrays(NULL, ports_array);

    return 0;
}
