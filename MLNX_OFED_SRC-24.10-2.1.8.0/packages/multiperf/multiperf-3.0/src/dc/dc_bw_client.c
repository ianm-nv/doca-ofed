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
#include <stdbool.h>
#include <errno.h>

struct test_ctx *global_ctx;

int create_dci_qp(struct test_ctx *ctx, int index)
{
    struct ibv_qp_init_attr_ex attr;
    struct mlx5dv_qp_init_attr attr_dv;
    enum ibv_wr_opcode opcode;
    memset(&attr, 0, sizeof(attr));
    memset(&attr_dv, 0, sizeof(attr_dv));

    attr.pd = ctx->pd;
    attr.send_cq = ctx->cq;
    attr.recv_cq = ctx->cq;
    attr.cap.max_inline_data = ctx->inl;
    attr.cap.max_send_wr = ctx->tx_depth;
    attr.cap.max_send_sge = MAX_SEND_SGE;
    attr.qp_type = IBV_QPT_DRIVER;
    attr.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS | IBV_QP_INIT_ATTR_PD;

    opcode = opcode_verbs_array[ctx->verb];
    if (opcode == IBV_WR_SEND)
        attr.send_ops_flags |= IBV_QP_EX_WITH_SEND;
    else if (opcode == IBV_WR_RDMA_WRITE)
        attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE;
    else if (opcode == IBV_WR_RDMA_READ)
        attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_READ;

    attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
    attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCI;
    attr_dv.create_flags |= MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE;
    attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;

    ctx->qp[index] = mlx5dv_create_qp(ctx->ctx, &attr, &attr_dv);
    if (ctx->qp[index] == NULL) {
        fprintf(stderr, "Unable to create DCT QP: %m.\n");
        return 1;
    }
    ctx->qpx[index] = ibv_qp_to_qp_ex(ctx->qp[index]);
    ctx->dv_qp[index] = mlx5dv_qp_ex_from_ibv_qp_ex(ctx->qpx[index]);

    return 0;
}

int init_ib_resources(struct test_ctx *ctx)
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
        for (i = 0; ctx->dev_list[i]; ++i) {
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

    ctx->cq = ibv_create_cq(ctx->ctx, ctx->tx_depth*ctx->num_of_qps, NULL, NULL, 0);
    if (!ctx->cq) {
        fprintf(stderr, "failed to create cq\n");
        return 1;
    }

    for (i = 0 ; i < ctx->num_of_qps; i++)
    {
        create_dci_qp(ctx, i);
        printf("created DCI=0x%.6x\n", ctx->qp[i]->qp_num);
        print_dci_to_logfile(ctx->logname, ctx->qp[i]->qp_num);
        if (!ctx->qp[i]) {
            fprintf(stderr, "failed to create qp\n");
            return 1;
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

int get_data_from_server(int sockfd, test_data *data)
{
    char msg[MSG_FORMAT_SIZE];
    int err = read(sockfd, msg, sizeof(msg));
    uint64_t subnet_prefix = 0, interface_id = 0;
    if (err != sizeof(msg)) {
        perror("client read");
        fprintf(stderr, "Read %d/%lu\n", err, sizeof(msg));
    }

    sscanf(msg, MSG_FORMAT,&data->dct_num, &data->dct_key, &data->lid,
        &subnet_prefix, &interface_id,
        &data->psn, &data->rkey, &data->vaddr, &data->srqn, &data->gid_index , &data->mtu);

    // due to those values are __be64, not uint64_t
    data->gid.global.subnet_prefix = subnet_prefix;
    data->gid.global.interface_id = interface_id;
    return 0;
}

void set_ah_attr(struct test_ctx *ctx, test_data *data, struct ibv_ah_attr* ah_attr)
{
    ah_attr->is_global = 1;
    ah_attr->dlid = data->lid;
    ah_attr->src_path_bits = 0;
    ah_attr->port_num = ctx->ib_port;
    ah_attr->grh.dgid = data->gid;
    ah_attr->grh.sgid_index = ctx->gid_index;
    ah_attr->grh.hop_limit = 0xFF;
    ah_attr->grh.traffic_class = ctx->tclass;
}

int create_ah(struct test_ctx *ctx, test_data *data, int ah_index)
{
    struct ibv_ah_attr ah_attr;
    memset(&ah_attr, 0, sizeof(ah_attr));
    set_ah_attr(ctx, data, &ah_attr);
    ctx->ah[ah_index] = ibv_create_ah(ctx->pd, &ah_attr);
    if (!ctx->ah[ah_index])
    {
        fprintf(stderr, "failed to create AH: %m\n");
        return -1;
    }
    return 1;
}

int modify_to_rts(struct test_ctx *ctx, test_data *data, int sl)
{
    int i;

    for (i = 0; i < ctx->num_of_qps; i++)
    {
        struct ibv_qp_attr attr;
        int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT;
        memset(&attr, 0, sizeof(attr));

        attr.qp_state        = IBV_QPS_INIT;
        attr.pkey_index      = 0;
        attr.port_num        = ctx->ib_port;
        if (ibv_modify_qp(ctx->qp[i], &attr, flags)) {
            fprintf(stderr, "Failed to modify QP to INIT: %m\n");
            return 1;
        }

        attr.qp_state                   = IBV_QPS_RTR;
        attr.path_mtu                   = (enum ibv_mtu)ctx->mtu;
        set_ah_attr(ctx, data, &attr.ah_attr);
        attr.ah_attr.sl                 = sl;

        if (ibv_modify_qp(ctx->qp[i], &attr,
            IBV_QP_STATE                  |
            IBV_QP_PATH_MTU)) {
            fprintf(stderr, "Failed to modify QP to RTR: %m\n");
            return 1;
        }

        attr.qp_state       = IBV_QPS_RTS;
        attr.timeout        = ctx->qp_timeout;
        attr.retry_cnt      = 7;
        attr.rnr_retry      = 7;
        attr.max_rd_atomic  = ctx->out_reads;
        if (ibv_modify_qp(ctx->qp[i], &attr,
            IBV_QP_STATE          |
            IBV_QP_TIMEOUT        |
            IBV_QP_RETRY_CNT      |
            IBV_QP_RNR_RETRY      |
            IBV_QP_SQ_PSN         |
            IBV_QP_MAX_QP_RD_ATOMIC)) {
            fprintf(stderr, "Failed to modify QP to RTS: %m\n");
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

static inline int do_post_send(struct test_ctx *ctx, test_data *data_arr,
    struct ibv_send_wr* wr, int inl, int index, int target)
{
    int rc;
    ibv_wr_start(ctx->qpx[index]);

    ctx->qpx[index]->wr_id = wr[index].wr_id;

    switch (wr[index].opcode) {
    case IBV_WR_SEND:
        ibv_wr_send(ctx->qpx[index]);
        break;
    case IBV_WR_RDMA_WRITE:
        ibv_wr_rdma_write(
            ctx->qpx[index],
            wr[index].wr.rdma.rkey,
            wr[index].wr.rdma.remote_addr);
        break;
    case IBV_WR_RDMA_READ:
        ibv_wr_rdma_read(
            ctx->qpx[index],
            wr[index].wr.rdma.rkey,
            wr[index].wr.rdma.remote_addr);
        break;
    default:
        fprintf(stderr, "Post send failed: unknown operation code.\n");;
    }

    mlx5dv_wr_set_dc_addr(
        ctx->dv_qp[index],
        ctx->ah[target],
        data_arr[target].dct_num,
        data_arr[target].dct_key);

    if (inl) {
        ibv_wr_set_inline_data(
            ctx->qpx[index],
            (void*)wr[index].sg_list->addr,
            ctx->size);
    } else {
        ibv_wr_set_sge(
            ctx->qpx[index],
            wr[index].sg_list->lkey,
            wr[index].sg_list->addr,
            ctx->size);
    }
    rc = ibv_wr_complete(ctx->qpx[index]);

    return rc;
}

int run_traffic(struct test_ctx *ctx, test_data *data_arr)
{
    uint64_t totscnt = 0;
    uint64_t totccnt = 0;
    uint64_t *scnt;
    uint64_t *ccnt;
    // we don't need wr to do a post send, but it is here for convenience
    struct ibv_send_wr *wr;
    struct ibv_sge  *sg_list;
    int err;
    int i;
    int ne;
    int qp_index;
    int is_inline = ctx->size <= ctx->inl;
    int poll_batch = 16;
    int n_targets = ctx->n_servers * ctx->n_ports;
    struct ibv_wc *wc = NULL;
    int busy_dci[ctx->num_of_qps];
    bool busy_target[n_targets];
    ALLOCATE(wr ,struct ibv_send_wr, ctx->num_of_qps);
    ALLOCATE(wc ,struct ibv_wc, poll_batch);
    ALLOCATE(sg_list, struct ibv_sge, ctx->num_of_qps);
    ALLOCATE(scnt, uint64_t, ctx->num_of_qps);
    ALLOCATE(ccnt, uint64_t, ctx->num_of_qps);
    memset(scnt, 0, ctx->num_of_qps*sizeof(uint64_t));
    memset(ccnt, 0, ctx->num_of_qps*sizeof(uint64_t));
    memset(busy_dci, -1, sizeof(busy_dci));
    memset(busy_target, 0, sizeof(busy_target));

    global_ctx=ctx;
    global_ctx->state = START_STATE;
    signal(SIGALRM, catch_alarm);
    if (ctx->margin > 0 ) alarm(ctx->margin);
    else catch_alarm(0); //move to next state

    ctx->iters = 0;

    for (i = 0; i < ctx->num_of_qps; i++)
    {
        memset(&wr[i], 0, sizeof(wr[i]));
        wr[i].num_sge = 1;
        wr[i].opcode = opcode_verbs_array[ctx->verb];
        ctx->qpx[i]->wr_flags = IBV_SEND_SIGNALED;
        sg_list[i].addr = ctx->my_addr[i];
        sg_list[i].length = ctx->size;
        sg_list[i].lkey = ctx->mr->lkey;
        wr[i].sg_list = &sg_list[i];
        wr[i].wr_id = i;

        if (is_inline)
        {
            ctx->qpx[i]->wr_flags |= IBV_SEND_INLINE;
        }
    }
    int target=0;
    while (global_ctx->state != END_STATE)
    {
        for(qp_index = 0; qp_index < ctx->num_of_qps; qp_index++)
        {

            if (-1 != busy_dci[qp_index]) continue;

            if (ctx->do_random_dest) target = rand()%n_targets;
            for (i=0; i < n_targets; i++) {
                target = (target+1)%n_targets;
                if (!busy_target[target]) break;
            }
            while ( (scnt[qp_index] - ccnt[qp_index]) < ctx->tx_depth )
            {
                if (ctx->verb == WRITE || ctx->verb == READ)
                {
                    wr[qp_index].wr.rdma.remote_addr = data_arr[target].vaddr;
                    wr[qp_index].wr.rdma.rkey = data_arr[target].rkey;
                }

                if (scnt[qp_index] % ctx->cq_mod == 0 && ctx->cq_mod > 1) {
                    ctx->qpx[qp_index]->wr_flags &= ~IBV_SEND_SIGNALED;
                }

                err = do_post_send(ctx, data_arr, wr, is_inline, qp_index, target);

                if (err) {
                    fprintf(stderr, "failed to post send request #%ld\n",ctx->iters + i);
                    return -1;
                }
                busy_dci[qp_index] = target;
                busy_target[target] = 1;
                totscnt += 1;
                scnt[qp_index] += 1;

                if (ctx->size <= (ctx->page_size / 2)) {
                    if (ctx->do_random_addr) {
                        increase_rand_loc_addr(wr[qp_index].sg_list,ctx->size,scnt[qp_index],ctx->my_addr[qp_index],0,ctx->cache_line_size,ctx->page_size, rand());
                        increase_rand_rem_addr(&wr[qp_index],ctx->size,scnt[qp_index],data_arr[target].vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size, rand());
                    }
                    else {
                        increase_loc_addr(wr[qp_index].sg_list,ctx->size,scnt[qp_index],ctx->my_addr[qp_index],0,ctx->cache_line_size,ctx->page_size);
                        increase_rem_addr(&wr[qp_index],ctx->size,scnt[qp_index],data_arr[target].vaddr,ctx->verb,ctx->cache_line_size,ctx->page_size);
                    }
                }

                if (scnt[qp_index]%ctx->cq_mod == (ctx->cq_mod - 1)) {
                    ctx->qpx[qp_index]->wr_flags |= IBV_SEND_SIGNALED;
                }

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
                        printf("Failure: %s\n", ibv_wc_status_str(wc[j].status));
                        fprintf(stderr, "completion with error %d\n", wc[j].status);
                        return -1;
                    }

                    if (global_ctx->state == SAMPLE_STATE)
                        ctx->iters += ctx->cq_mod;

                    ccnt[wc[j].wr_id] += ctx->cq_mod;
                    busy_target[busy_dci[wc[j].wr_id]] = 0;
                    busy_dci[wc[j].wr_id] = -1;
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
    int server_iter, port_iter, i;

    for (server_iter=0 ; server_iter<ctx->n_servers ; server_iter++) {
        for (port_iter=0 ; port_iter<ctx->n_ports ; port_iter++) {
            if (ibv_destroy_ah(ctx->ah[server_iter * ctx->n_ports + port_iter])) {
                fprintf(stderr, "failed to destroy AH\n");
                test_result = 1;
            }
        }
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
    free(ctx->qpx);
    free(ctx->dv_qp);
    free(ctx->ah);

    return test_result;
}

char* create_logname_client(char* file_path) {
    char* name = "/dc_client_logfile";
    char *result = malloc(strlen(file_path) + strlen(name)+1);//+1 for the null-terminator
    strcpy(result, file_path);
    strcat(result, name);
    return result;
}

int main(int argc, char *argv[])
{
    struct test_ctx ctx;
    test_data *data_arr;
    int		sockfd = 0;
    int		pid = 0;
    int		i, iterations, server_iter, port_iter, sl_random, port_index;

    ibv_fork_init();

    init_ctx(&ctx, argc, argv, 1);

    FILE* file;
    if (NULL != ctx.file_path) {
        ctx.logname = create_logname_client(ctx.file_path);
        printf("logname: %s\n", ctx.logname);
        file = fopen(ctx.logname, "w");
        if (NULL == file) {
            fprintf(stderr, "Error opening file! Please check the file_path you gave (-F)\n");
            exit(1);
        }
    }

    print_command(ctx.logname, argc, argv);

    // parse servers & ports
    char **servers_array = (char**)malloc((ctx.n_servers+1)*sizeof(*servers_array));
    char **ports_array = (char**)malloc((ctx.n_ports+1)*sizeof(*ports_array));
    if (parse_server_list(&ctx, &servers_array) ||
        parse_port_list  (&ctx, &ports_array  ) ){
        destroy_arrays(servers_array, ports_array);
        exit(1);
    }
    ALLOCATE(data_arr ,test_data, ctx.n_servers * ctx.n_ports);
    ALLOCATE(ctx.ah ,struct ibv_ah*, ctx.n_servers * ctx.n_ports);

    for (iterations=0; iterations<ctx.iterations; iterations++) {
        print_iteration(iterations+1, ctx.logname);

        for(i = 0; i < ctx.processes; i++) // notice, also for 1 process, there will be a fork.
        {
            pid = fork();
            if (0 == pid) // child, then exit the loop
                break;
        }
        if (0 == pid)
        {
            sl_random = (ctx.tclass >> 5)%6;//rand() % 6;  // sl is random in range [0...5]  # TODO 6/7 doesnt work...
            if (init_ib_resources(&ctx)) {
                fprintf(stderr, "Failed to create IB resources: %m\n");
                exit(1);
            }
            for (server_iter=0 ; server_iter<ctx.n_servers ; server_iter++) {
                for (port_iter=0 ; port_iter<ctx.n_ports ; port_iter++) {
                    sockfd = start_connection(servers_array[server_iter], strtol(ports_array[port_iter], NULL, 0));
                    get_data_from_server(sockfd, &data_arr[server_iter * ctx.n_ports + port_iter]);
                }
            }
            if (modify_to_rts(&ctx, &data_arr[0], sl_random)) {
                fprintf(stderr, "Failure while moving DCI QP to RTS: %m\n");
                exit(1);
            }
            for (server_iter=0 ; server_iter<ctx.n_servers ; server_iter++) {
                for (port_iter=0 ; port_iter<ctx.n_ports ; port_iter++) {
                    port_index = server_iter * ctx.n_ports + port_iter;
                    create_ah(&ctx, &data_arr[port_index], port_index);
                }
            }
            run_traffic(&ctx, data_arr);
            destroy_resources(&ctx);
            close(sockfd);
        }

        while(wait(NULL) > 0);
        if (0 == pid) { // child, then exit the loop.
            break;
        }
    }

    while(wait(NULL) > 0);
    destroy_arrays(servers_array, ports_array);
    if (0 != pid) print_end_of_test_client(ctx.logname);
    return 0;
}
