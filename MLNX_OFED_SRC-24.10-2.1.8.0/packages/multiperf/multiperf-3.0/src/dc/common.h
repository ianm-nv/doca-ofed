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
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#include "src/common_global.h"
#include <signal.h>

//#define MSG_FORMAT "000000:0000000000000000:000000:0000000000000000:0000000000000000:000000:0000000000000000:0000000000000000:00000000000000000000:000000:000000:0000"
//                dctnum:       dctkey: lid:        gid_h:        gid_l: psn:rkey:        vaddr:srqn:gididx:mtu
#define MSG_FORMAT "%06x:%16" PRIx64 ":%04x:%16" PRIx64 ":%16" PRIx64 ":%06x:%08x:%16" PRIx64 ":%08x:%06x:%04x"
#define MSG_FORMAT_SIZE 105

#define PAGE_SIZE 4096
#define MAX_SEND_SGE (1)

// Macro for allocating.
#define ALLOCATE(var,type,size)                                     \
    { if((var = (type*)malloc(sizeof(type)*(size))) == NULL)        \
    { fprintf(stderr," Cannot Allocate\n"); exit(1);}}

#define GET_STRING(orig,temp){ ALLOCATE(orig,char,(strlen(temp) + 1)); strcpy(orig,temp); }

#define BUFF_SIZE(size,cycle_buffer) ((size < cycle_buffer) ? (cycle_buffer) : (size))

// Macro that defines the adress where we write in RDMA.
// // If message size is smaller then CACHE_LINE size then we write in CACHE_LINE jumps.
#define INC(size,cache_line_size) ((size > cache_line_size) ? ((size%cache_line_size == 0) ?  \
                (size) : (cache_line_size*(size/cache_line_size+1))) : (cache_line_size))

#define CHECK_VALUE(arg,type,minv,maxv,name)                                                                                    \
        { arg = (type)strtol(optarg, NULL, 0); if ((arg < minv) || (arg > maxv))                \
        { fprintf(stderr," %s should be between %d and %d\n",name,minv,maxv); return 1; }}

typedef enum { SEND , WRITE, READ } VerbType;

static enum ibv_wr_opcode opcode_verbs_array[] = {IBV_WR_SEND,IBV_WR_RDMA_WRITE,IBV_WR_RDMA_READ,IBV_WR_RDMA_READ};

typedef struct data {
    uint32_t			dct_num;
    uint64_t dct_key;
    int			lid;
    union ibv_gid		gid;
    int			psn;
    unsigned		rkey;
    uint64_t	vaddr;
    unsigned		srqn;
    int			gid_index;
    int			mtu;
} test_data;

typedef struct {
    int *socket;
    test_data data;
    int tcp_port;
    char* logname;
} handler_data;

typedef enum { START_STATE, SAMPLE_STATE, STOP_SAMPLE_STATE, END_STATE} DurationStates;

struct test_ctx {
    struct ibv_qp           **qp;
    struct mlx5dv_qp_ex     **dv_qp;
    struct ibv_qp_ex        **qpx;
    struct ibv_cq           *cq;
    struct ibv_pd           *pd;
    struct ibv_mr           *mr;
    struct ibv_ah           **ah;
    struct ibv_srq          *srq;
    struct ibv_context      *ctx;
    void                    *addr;
    uintptr_t		        *my_addr;
    size_t                  length;
    int                     port;
    char*				    port_str;
    uint64_t                dct_key;
    uint32_t                dct_num;
    uint64_t                gid_index;
    int                     tclass;
    union ibv_gid           gid;
    unsigned                size;
    int                     ib_port;
    enum ibv_mtu            mtu;
    int                     user_mtu;
    int                     rcv_idx;
    struct ibv_port_attr    portinfo;
    int                     inl;
    struct ibv_device       **dev_list;
    struct ibv_device       *ib_dev;
    char                    *ib_devname;
    enum ctx_device		    device_name_by_id;
    uint64_t		iters;
    int			duration;
    int			margin;
    DurationStates		state;
    struct timeval		start;
    struct timeval		end;
    int                     use_event;
    uint32_t		srqn;
    char			*servername;
    char			*ports;
    int			processes;
    int			tx_depth;
    int			rx_depth;
    int			report_mbytes;
    int			num_of_qps;
    int			page_size;
    int			cache_line_size;
    VerbType		verb;
    int			use_contig_pages;
    int			out_reads;
    int			cq_mod;
    int			qp_timeout;
    int			do_random_dest;
    int			do_random_addr;
    int 			iterations;
    struct ibv_sge		recv_sge_list;
    uintptr_t		rx_buffer_addr;
    struct ibv_recv_wr	rwr;
    unsigned random_seed;
    int n_servers;
    int n_ports;
    char* file_path;
    char* logname;
};

static inline int to_ib_mtu(int mtu, enum ibv_mtu *ibmtu)
{
    switch (mtu) {
        case 256:
            *ibmtu = IBV_MTU_256;
            return 0;
        case 512:
            *ibmtu = IBV_MTU_512;
            return 0;
        case 1024:
            *ibmtu = IBV_MTU_1024;
            return 0;
        case 2048:
            *ibmtu = IBV_MTU_2048;
            return 0;
        case 4096:
            *ibmtu = IBV_MTU_4096;
            return 0;
        default:
            return -1;
    }
}

// doc: check if a string is an integer (contains only digits).
// return: 1 if str is an integer. 0 if it's not.
int numbers_only(const char *s)
{
    int i;
    for (i = 0; i < strlen(s); i++){
    if ( s[i]<'0' || s[i] > '9') return 0;
    }
    return 1;
}

// doc: check if a string is an integer.
// return: 1 if it is an integer. 0 if it's not.
int is_integer(char* str) {
    float num = strtof(str, NULL);
    if ( !numbers_only(str) || (num - (int)num != 0)) return 0;
    return 1;
}

void print_iteration(int iter, char* logname) {
    FILE* file;
    printf("\n\nStart iteration %d.\n", iter);
    if (logname) {
        file = fopen(logname, "a"); // write to the end of the file.
        fprintf(file, "\n\nStart iteration %d.\n", iter);
        fclose(file);
    }
}

void print_command(char* logname, int argc, char *argv[]) {
    printf("\nCommand:\n");
    int aa;
    for (aa=0; aa<argc ; aa++) {
        printf("%s ",argv[aa]);
    }
    printf("\n\n");

    FILE* file;
    if (logname) {
        file = fopen(logname, "a"); // write to the end of the file.
        fprintf(file, "\nCommand:\n");
        for (aa=0; aa<argc ; aa++) {
            fprintf(file, "%s ",argv[aa]);
        }
        fprintf(file, " ");
        fclose(file);
    }
}

void print_end_of_test_client(char* logname) {
    FILE* file;
    printf("\n\nEnd of Test, Client.\n\n");
    if (logname) {
        file = fopen(logname, "a"); // write to the end of the file.
        fprintf(file, "\n\nEnd of Test, Client.\n\n");
        fclose(file);
    }
}

// DEBUG
void print_error(char* str) {
    printf("Error Ido: %s.\n", str);
}

// DEBUG
void print_connection(char* ip, int listen_port, int conn_port) {
    printf("New connection from client IP: %s, listen_port: %d, port: %d\n", ip, listen_port, conn_port);
}

void print_dci_to_logfile(char* logname, int qp_num) {
    FILE* file;
    if (logname) {
        file = fopen(logname, "a"); // write to the end of the file.
        fprintf(file, "created DCI=0x%.6x\n", qp_num);
        fclose(file);
    }
}

void print_bw_report_to_logfile(char* logname, uint64_t iters, float bw_result, uint64_t mr_result) {
    FILE* file;
    if (logname) {
        file = fopen(logname, "a"); // write to the end of the file.
        fprintf(file, "Iters = %ld , BW = %.2f MB/s , MR = %.5" PRId64 " Mpps\n", iters, bw_result, mr_result);
        fclose(file);
    }
}


void usage(const char *argv0)
{
    printf("  %s     	start a server and wait for a connection\n", ".../dc_bw_server");
    printf("  %s 	One to many client. --server_ports <host1>...<hostS> --server_ports <port1>...<portP> connect to each server, to each port. Total to S*P servers in parallel.\n", ".../dc_bw_client");
    printf("\n");
    printf("Flags:\n");

    printf("  -F, -file_path    	 the file path it which the server/client log will be saved (in addition to the terminal).\n		  	 For server log will be: <file_path>/dc_server_logfile_port_<port>.  For client log will be: <file_path>/dc_client_logfile\n");
    printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
    printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
    printf("  -s, --size=<size>      size of message to exchange (default 65536)\n");
    printf("  -k, --dc-key           DC transport key\n");
    printf("  -x, --gix=<gid_infex>  GID index to use\n");
    printf("  -m, --mtu              MTU to use\n");
    printf("  -q, --qps              Set Number of QPs to use\n");
    printf("  -n, --inline           Requested inline size\n");
    printf("  -P, --processes        Number of processes to run (default 1)\n");
    printf("  -f, --margin		 Set Margin value(default 0)\n");
    printf("  -D, --duration         Set Duration value (default 3)\n");
    printf("  -t, --tx-depth         Set TX Depth value(default 100)\n");
    printf("  -B  --report_mbytes    Report BW in MB/s units\n");
    printf("  -o  --outs		 Num of outstanding read (default 16)\n");
    printf("  -Q  --cq_mod		 Set CQ Mod value (default 100)\n");
    printf("  -u  --qp_timeout       Set QP Timeout (default 14)\n");
    printf("  -T  --tclass           traffic class\n");
    printf("  -R  --random_dest      Use Random destination for each DCI (default is round-robin on destinations)\n");
    printf("  -M  --random_mem       Use Random addresses inside memory region\n");

    printf("\n");
    printf("Client flags:\n");
    printf("  -v  --verb		 Set Verb to use: WRITE / READ/SEND\n");
    printf("  -S  --servers          list of servers (the client connects each of them). Example: clx-app-008,clx-app-008,clx-app-009\n");
    printf("  -p  --server_ports     list of server ports (the client connects each of them). Example: 18516,18517,18518 (default 18515).\n");
    printf("  -I, --iterations       Set number of iterations (default 1).  In each iteration the client sends to all the servers.\n");

    printf("\n");
    printf("Server flags:\n");
    printf("  -p  --port             listen on port <port> (default 18515).\n");
    printf("\n");
}

int parse(struct test_ctx *ctx, int argc, char *argv[])
{

    srand48(getpid() * time(NULL));
    int mtu, size_factor = 1, size_len;
    char *verb;

    while (1) {
        int c;

        static struct option long_options[] = {
            { .name = "file_path",		.has_arg = 1, .val = 'F' },
            { .name = "servers",		.has_arg = 1, .val = 'S' },
            { .name = "server_ports",		.has_arg = 1, .val = 'p' },
            { .name = "ib-dev",		.has_arg = 1, .val = 'd' },
            { .name = "ib-port",		.has_arg = 1, .val = 'i' },
            { .name = "size",		.has_arg = 1, .val = 's' },
            { .name = "dc-key",		.has_arg = 1, .val = 'k' },
            { .name = "gix",		.has_arg = 1, .val = 'x' },
            { .name = "mtu",		.has_arg = 1, .val = 'm' },
            { .name = "qps",		.has_arg = 1, .val = 'q' },
            { .name = "inline",		.has_arg = 1, .val = 'n' },
            { .name = "processes",		.has_arg = 1, .val = 'P' },
            { .name = "duration",		.has_arg = 1, .val = 'D' },
            { .name = "iterations",		.has_arg = 1, .val = 'I' },
            { .name = "margin",		.has_arg = 1, .val = 'f' },
            { .name = "tx-depth",		.has_arg = 1, .val = 't' },
            { .name = "report_mbytes",	.has_arg = 0, .val = 'B' },
            { .name = "outs",		.has_arg = 1, .val = 'o' },
            { .name = "verb",		.has_arg = 1, .val = 'v' },
            { .name = "cq_mod",		.has_arg = 1, .val = 'Q' },
            { .name = "qp_timeout",		.has_arg = 1, .val = 'u' },
            { .name = "tclass",		.has_arg = 1, .val = 'T' },
            { .name = "random_dest",		.has_arg = 0, .val = 'R' },
            { .name = "random_mem",		.has_arg = 0, .val = 'M' },
            { 0 }
        };

        c = getopt_long(argc, argv, "F:S:p:d:i:s:k:x:m:q:n:P:D:I:f:t:Bo:v:Q:u:T:RM", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
            case 'S':
                GET_STRING(ctx->servername,strdup(optarg));
                break;

            case 'p':
                GET_STRING(ctx->ports,strdup(optarg));
                ctx->port = strtol(optarg, NULL, 0);
                break;

            case 'F':
                GET_STRING(ctx->file_path,strdup(optarg));
                break;

            case 'd':
                GET_STRING(ctx->ib_devname,strdup(optarg));
                break;

            case 'v':
                GET_STRING(verb,strdup(optarg));
                if (!strcmp(verb,"WRITE"))
                    ctx->verb = WRITE;
                else if (!strcmp(verb,"READ"))
                    ctx->verb = READ;
                else if (!strcmp(verb,"SEND"))
                    ctx->verb = SEND;
                else
                {
                    fprintf(stderr,"invalid verb [-v] selection (Should be WRITE/READ/SEND)\n\n");
                    return 1;
                }
                break;

            case 'n':
                ctx->inl = strtol(optarg, NULL, 0);
                if (ctx->inl < 0) {
                    fprintf(stderr, "inline [-n] has to be positive.\n");
                    return 1;
                }
                break;

            case 'i':
                ctx->ib_port = strtol(optarg, NULL, 0);
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "ib_port [-i] has to be an integer.\n");
                    return 1;
                }
                if (ctx->ib_port < 0) {
                    fprintf(stderr, "ib_port [-i] has to be positive.\n");
                    return 1;
                }
                break;

            case 'm':
                mtu = strtol(optarg, NULL, 0);
                ctx->user_mtu=1;
                if (to_ib_mtu(mtu, &ctx->mtu)) {
                    printf("invalid MTU %d\n", mtu);
                    return 1;
                }
                break;

            case 's':
                size_len = (int)strlen(optarg);
                if (optarg[size_len-1] == 'K') {
                    optarg[size_len-1] = '\0';
                    size_factor = 1024;
                }
                if (optarg[size_len-1] == 'M') {
                    optarg[size_len-1] = '\0';
                    size_factor = 1024*1024;
                }
                ctx->size = (uint64_t)strtol(optarg, NULL, 0) * size_factor;
                if (ctx->size < 1 || ctx->size > (UINT_MAX / 2)) {
                    fprintf(stderr," Message Size should be between %d and %d\n",1,UINT_MAX/2);
                    return 1;
                }
                break;

            case 'k':
                ctx->dct_key = strtoull(optarg, NULL, 0);
                break;

            case 'x':
                ctx->gid_index = strtoull(optarg, NULL, 0);
                break;
            case 'P':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "processes [-P] has to be an integer.\n");
                    return 1;
                }
                ctx->processes = strtol(optarg, NULL, 0);
                break;

            case 'o':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "out_reads [-o] has to be an integer.\n");
                    return 1;
                }
                ctx->out_reads = strtol(optarg, NULL, 0);
                break;

            case 'D':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "duration [-D] has to be an integer.\n");
                    return 1;
                }
                ctx->duration = strtol(optarg, NULL, 0);
                break;

            case 'I':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "iterations [-I] has to be an integer.\n");
                    return 1;
                }
                ctx->iterations = strtol(optarg, NULL, 0);
                break;

            case 'f':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "margin [-f] has to be an integer.\n");
                    return 1;
                }
                ctx->margin = strtol(optarg, NULL, 0);
                break;

            case 't':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "tx_depth [-t] has to be an integer.\n");
                    return 1;
                }
                ctx->tx_depth = strtol(optarg, NULL, 0);
                break;

            case 'u':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "qp_timeout [-u] has to be an integer.\n");
                    return 1;
                }
                ctx->qp_timeout = strtol(optarg, NULL, 0);
                break;

            case 'T':
                ctx->tclass = strtol(optarg, NULL, 0);
                break;


            case 'B':
                ctx->report_mbytes = 1;
                break;

            case 'Q':
                CHECK_VALUE(ctx->cq_mod,int,1,1024,"CQ moderation");
                break;

            case 'q':
                if (is_integer(optarg) == 0) { // not an integer
                    fprintf(stderr, "Number of QPs [-q] has to be an integer.\n");
                    return 1;
                }
                ctx->num_of_qps = strtol(optarg, NULL, 0);
                break;

            case 'R':
                ctx->do_random_dest = 1;
                break;

            case 'M':
                ctx->do_random_addr = 1;
                break;

            default:
                usage(argv[0]);
                return 1;
        }
    }

    // make sure all args are legal
    if (optind < argc) {
        usage(argv[0]);
        return 1;
    }

    return 0;
}

void copy_test_data(test_data *src, test_data *dest)
{
    dest->dct_num	= src->dct_num;
    dest->dct_key	= src->dct_key;
    dest->lid	= src->lid;
    dest->gid	= src->gid;
    dest->psn	= src->psn;
    dest->rkey	= src->rkey;
    dest->srqn	= src->srqn;
    dest->vaddr	= src->vaddr;
    dest->gid_index	= src->gid_index;
    dest->mtu	= src->mtu;
}

void destroy_arrays(char** servers_array, char** ports_array)
{
    free (servers_array);
    free (ports_array);
}

int parse_server_list(struct test_ctx *ctx, char*** servers_array)
{
    char *break_char=",";
    if (NULL == ctx->servername) {
        fprintf(stderr, "Parser Error! Please supply lists of Servers [-S].\n");
        return 1;
    }

    //parse servers
    char *local_servernames = malloc(sizeof(char) * strlen(ctx->servername));
    strcpy(local_servernames,ctx->servername);

    (*servers_array)[ctx->n_servers] = strtok(local_servernames, break_char);
    while ((*servers_array)[ctx->n_servers] != NULL) {
        ctx->n_servers++;
        (*servers_array) = (char**)realloc((*servers_array), (ctx->n_servers+1)*sizeof(*(*servers_array)));
        (*servers_array)[ctx->n_servers] = strtok(NULL,break_char);
    }

    return 0;
}

int parse_port_list(struct test_ctx *ctx, char*** ports_array)
{
    char *break_char=",";
    if (NULL == ctx->ports) {
        fprintf(stderr, "Parser Error! Please supply lists of ports [-p].\n");
        return 1;
    }

    // parse ports
    char *local_ports = malloc(sizeof(char) * strlen(ctx->ports));
    strcpy(local_ports,ctx->ports);

    (*ports_array)[ctx->n_ports] = strtok(local_ports, break_char);
    while ((*ports_array)[ctx->n_ports] != NULL) {
        ctx->n_ports++;

        (*ports_array) = (char**)realloc((*ports_array), (ctx->n_ports+1)*sizeof(*(*ports_array)));
        (*ports_array)[ctx->n_ports] = strtok(NULL,break_char);
    }

    int port;
    int i; for (i=0; i < ctx->n_ports; i++){
        port = strtol((*ports_array)[i], NULL, 0);
        if (port < 0 || port > 65535) {
            fprintf(stderr, "Error! port [-p] has to be in range [0,65535]. Your port is: %d\n", port);
            return 1;
        }
    }

    return 0;
}

void init_ctx_defaults(struct test_ctx *ctx)
{
    srand(time(NULL)); // TODO take seed from input
    ctx->random_seed = rand();
    ctx->port		= 18515;
    ctx->port_str = "18515";
    ctx->ib_port		= 1;
    ctx->dct_key		= rand();
    ctx->gid_index		= 3;
    ctx->size		= 65536;
    ctx->mtu		= IBV_MTU_512;
    ctx->user_mtu   = 0;
    ctx->inl		= 0;
    ctx->ib_devname		= NULL;
    ctx->servername		= NULL;
    ctx->ports		= NULL;
    ctx->iters		= 10000;
    ctx->duration		= 3;
    ctx->margin		= 0;
    ctx->processes		= 1;
    ctx->tx_depth		= 8;
    ctx->rx_depth		= 1;
    ctx->report_mbytes	= 0;
    ctx->page_size		= PAGE_SIZE;
    ctx->cache_line_size	= 64;
    ctx->num_of_qps		= 1;
    ctx->out_reads		= 16;
    ctx->cq_mod		= 100;
    ctx->qp_timeout         = 14;
    ctx->do_random_addr     = 0;
    ctx->do_random_dest     = 0;
    ctx->iterations     = 1;
    ctx->verb		= WRITE;
    ctx->n_servers= 0;
    ctx->n_ports = 0;
    ctx->file_path = NULL;
    ctx->logname = NULL;
}

void init_ctx(struct test_ctx *ctx, int argc, char *argv[], int client)
{
    init_ctx_defaults(ctx);
    if (parse(ctx,argc,argv)) {
        exit(1);
    }

    if (ctx->inl != 0 && ctx->verb == READ)
    {
        fprintf(stderr, "Inline is not supported in READ\n");
        ctx->inl = 0;
    }

    if (ctx->cq_mod > ctx->tx_depth)
    {
        ctx->cq_mod = ctx->tx_depth;
//         fprintf(stderr,"Setting cq_mod = %d\n", ctx->cq_mod);
    }

    if (ctx->do_random_addr)
    {
        ctx->page_size = 2*PAGE_SIZE*ctx->do_random_addr;
    }

    if (ctx->verb == SEND)
    {
        ctx->rx_depth = 512;
    }

    ALLOCATE(ctx->qp,struct ibv_qp*,ctx->num_of_qps);
    ALLOCATE(ctx->qpx,struct ibv_qp_ex*,ctx->num_of_qps);
    ALLOCATE(ctx->dv_qp,struct mlx5dv_qp_ex*,ctx->num_of_qps);
    ALLOCATE(ctx->my_addr,uintptr_t,ctx->num_of_qps);
}

int init_test_data(struct test_ctx *ctx, test_data *data)
{
    data->dct_num	= ctx->dct_num;
    data->dct_key	= ctx->dct_key;
    data->lid	= ctx->portinfo.lid;
    data->gid	= ctx->gid;
    data->psn	= 0;
    data->rkey	= ctx->mr->rkey;
    data->srqn	= ctx->srqn;
    data->vaddr	= (uintptr_t)ctx->addr;
    data->gid_index	= ctx->gid_index;
    data->mtu	= (int)ctx->mtu;

    return 1;
}

static __inline void increase_loc_addr(struct ibv_sge *sg,int size,uint64_t rcnt,uint64_t prim_addr,int server_is_ud, int cache_line_size, int cycle_buffer)
{
    sg->addr += INC(size,cache_line_size);
    if ( ((rcnt+1) % (cycle_buffer/ INC(size,cache_line_size))) == 0 )
        sg->addr = prim_addr;
}

static __inline void increase_rem_addr(struct ibv_send_wr *wr,int size,uint64_t scnt,uint64_t prim_addr,VerbType verb, int cache_line_size, int cycle_buffer)
{
    wr->wr.rdma.remote_addr += INC(size,cache_line_size);

    if ( ((scnt+1) % (cycle_buffer/ INC(size,cache_line_size))) == 0) {
        wr->wr.rdma.remote_addr = prim_addr;
    }
}

static __inline void increase_rand_loc_addr(struct ibv_sge *sg,int size,uint64_t rcnt,uint64_t prim_addr,int server_is_ud, int cache_line_size, int cycle_buffer, int n)
{
    int steps = n % (cycle_buffer / INC(size,cache_line_size));
    sg->addr = prim_addr + steps*INC(size,cache_line_size);
}

static __inline void increase_rand_rem_addr(struct ibv_send_wr *wr,int size,uint64_t scnt,uint64_t prim_addr,VerbType verb, int cache_line_size, int cycle_buffer, int n)
{
    int steps = n % (cycle_buffer / INC(size,cache_line_size));
    wr->wr.rdma.remote_addr = prim_addr + steps*INC(size,cache_line_size);
}

static int create_mr(struct test_ctx *ctx)
{
    ctx->length = 2*BUFF_SIZE(ctx->size,ctx->page_size)*ctx->num_of_qps;
    ctx->addr = NULL;

    ctx->addr = memalign(ctx->page_size,ctx->length);
    if (!ctx->addr) {
        fprintf(stderr, "failed to allocate memory\n");
        return -1;
    }
    memset(ctx->addr, 0, ctx->length);
    ctx->mr = ibv_reg_mr(ctx->pd, ctx->addr, ctx->length,
                            IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);

    if (!ctx->mr) {
        fprintf(stderr, "failed to create mr\n");
        return -1;
    }

    return 0;
}

void print_bw_report(struct test_ctx *ctx)
{
    float usec = (ctx->end.tv_sec - ctx->start.tv_sec) * 1000000 +
    (ctx->end.tv_usec - ctx->start.tv_usec);
    long long bytes = (long long) ctx->size * ctx->iters;

    float bw = (8*bytes)/(usec);

    if (ctx->report_mbytes) {
        printf("Iters = %ld , BW = %.2f MB/s , MR = %.5f Mpps\n",
                  ctx->iters, (1000*1000*bw)/(1024*1024*8), ctx->iters/(usec));
        print_bw_report_to_logfile(ctx->logname, ctx->iters,
                                                   (1000*1000*bw)/(1024*1024*8), ctx->iters/(usec));
    }else {
        printf("Iters = %ld , BW = %.5f Gb/s , MR = %.5f Mpps\n",
                          ctx->iters, bw/(1000), ctx->iters/(usec));
        print_bw_report_to_logfile(ctx->logname, ctx->iters, bw/(1000), ctx->iters/(usec));
    }
}