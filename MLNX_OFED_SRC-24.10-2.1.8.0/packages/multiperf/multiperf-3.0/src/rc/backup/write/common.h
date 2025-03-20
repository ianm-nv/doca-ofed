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
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>

//#define MSG_FORMAT "000000:000000:000000:000000:0000000000000000:0000000000000000:00000000000000000000:000000:000000:0000"
//                   dctnum:dctkey:lid:psn:rkey:vaddr:srqn:gididx:mtu
#define MSG_FORMAT "%06x:%16llx:%04x:%06x:%08x:%16Lx:%08x:%06x:%04x"
#define MSG_FORMAT_SIZE 82

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

typedef enum { SEND , WRITE, READ, ATOMIC } VerbType;

typedef struct data {
	struct ibv_qp		*qp;
	int			qp_num;
	int			lid;
	int			psn;
	unsigned		rkey;
	unsigned long long	vaddr;
	union ibv_gid		gid;
	unsigned		srqn;
	int			gid_index;
	int			mtu;
	} test_data;

typedef struct {
	int *socket;
	test_data data;
	int tcp_port;
	int ib_port;
} handler_data;

typedef enum { START_STATE, SAMPLE_STATE, STOP_SAMPLE_STATE, END_STATE} DurationStates;

struct test_ctx {
	struct ibv_qp           **qp;
	struct ibv_cq           *cq;
	struct ibv_pd           *pd;
	struct ibv_mr           *mr;
	struct ibv_ah		*ah;
	struct ibv_context      *ctx;
	void                    *addr;
	uintptr_t		*my_addr;
	size_t                  length;
	int                     port;
	unsigned                size;
	int                     ib_port;
	enum ibv_mtu            mtu;
	struct ibv_port_attr    portinfo;
	int                     inl;
	struct ibv_device       **dev_list;
	struct ibv_device       *ib_dev;
	char                    *ib_devname;
	uint64_t		iters;
	int			duration;
	int			margin;
	DurationStates		state;
	struct timeval		start;
	struct timeval		end;
	int                     use_event;
	char			*servername;
	int			processes;
	int			tx_depth;
	int			rx_depth;
	int			report_mbytes;
	int			num_of_qps;
	int			page_size;
	int			cache_line_size;
	VerbType		verb;
	int			gid_index;
	int			sl;
	int			use_contig_pages;
	int			*socket;
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

void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n", argv0);
	printf("  %s <host>     connect to server at <host>\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
	printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
	printf("  -s, --size=<size>      size of message to exchange (default 65536)\n");
	printf("  -k, --dc-key           DC transport key\n");
	printf("  -m, --mtu              MTU to use\n");
	printf("  -I, --inline           Requested inline size\n");
	printf("  -P, --processes        Number of processes to run (default 1)\n");
	printf("  -D, --duration         Set Duration value(default 3)\n");
	printf("  -f, --margin		 Set Margin value(default 0)\n");
	printf("  -t, --tx-depth         Set TX Depth value(default 100)\n");
	printf("  -q, --num_of_qps       Set Number of QPs to open(default 1)\n");
	printf("  -M  --report_mbytes    Report BW in MB/s units\n");
}

int parse(struct test_ctx *ctx, int argc, char *argv[])
{
	srand48(getpid() * time(NULL));
	int mtu, size_factor = 1, size_len;

        while (1) {
                int c;

                static struct option long_options[] = {
                        { .name = "port",       .has_arg = 1, .val = 'p' },
                        { .name = "ib-dev",     .has_arg = 1, .val = 'd' },
                        { .name = "ib-port",    .has_arg = 1, .val = 'i' },
                        { .name = "size",       .has_arg = 1, .val = 's' },
                        { .name = "dc-key",     .has_arg = 1, .val = 'k' },
                        { .name = "mtu",        .has_arg = 1, .val = 'm' },
                        { .name = "inline",     .has_arg = 1, .val = 'I' },
                        { .name = "processes",     .has_arg = 1, .val = 'P' },
                        { .name = "duration",     .has_arg = 1, .val = 'D' },
                        { .name = "margin",     .has_arg = 1, .val = 'f' },
                        { .name = "tx-depth",     .has_arg = 1, .val = 't' },
                        { .name = "num_of_qps",   .has_arg = 1, .val = 'q' },
                        { .name = "report_mbytes",     .has_arg = 0, .val = 'M' },
                        { 0 }
                };

                c = getopt_long(argc, argv, "p:d:i:s:k:m:I:P:D:t:f:q:M", long_options, NULL);
                if (c == -1)
                        break;

                switch (c) {
                case 'p':
                        ctx->port = strtol(optarg, NULL, 0);
                        if (ctx->port < 0 || ctx->port > 65535) {
                                usage(argv[0]);
                                return 1;
                        }
                        break;

                case 'd':
			GET_STRING(ctx->ib_devname,strdupa(optarg));
                        break;

                case 'I':
                        ctx->inl = strtol(optarg, NULL, 0);
                        if (ctx->inl < 0) {
                                usage(argv[0]);
                                return 1;
                        }
                        break;

                case 'i':
                        ctx->ib_port = strtol(optarg, NULL, 0);
                        if (ctx->ib_port < 0) {
                                usage(argv[0]);
                                return 1;
                        }
                        break;

                case 'm':
                        mtu = strtol(optarg, NULL, 0);
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

		case 'P':
			ctx->processes = strtol(optarg, NULL, 0);
			break;

		case 'D':
			ctx->duration = strtol(optarg, NULL, 0);
			break;

		case 'f':
			ctx->margin = strtol(optarg, NULL, 0);
			break;

		case 't':
			ctx->tx_depth = strtol(optarg, NULL, 0);
			break;

		case 'q':
			ctx->num_of_qps = strtol(optarg, NULL, 0);
			break;

		case 'M':
			ctx->report_mbytes = 1;
			break;

                default:
                        usage(argv[0]);
                        return 1;
                }
        }

        if (optind == argc - 1) {
                GET_STRING(ctx->servername,strdupa(argv[optind]));
        } else if (optind < argc) {
                usage(argv[0]);
                return 1;
        }

	return 0;
}

void copy_test_data(test_data *src, test_data *dest)
{
	dest->qp	= src->qp;
	dest->qp_num	= src->qp_num;
	dest->lid	= src->lid;
	dest->gid	= src->gid;
	dest->psn	= src->psn;
	dest->rkey	= src->rkey;
	dest->srqn	= 0;
	dest->vaddr	= src->vaddr;
	dest->gid_index	= src->gid_index;
	dest->mtu	= src->mtu;
}

int init_ctx(struct test_ctx *ctx, int argc, char *argv[], int to_parse)
{
	ctx->port		= 18515;
	ctx->ib_port		= 1;
	ctx->size		= 65536;
	ctx->mtu		= IBV_MTU_4096;
	ctx->inl		= 0;
	ctx->ib_devname		= NULL;
	ctx->iters		= 10000;
	ctx->duration		= 3;
	ctx->margin		= 0;
	ctx->processes		= 1;
	ctx->tx_depth		= 128;
	ctx->rx_depth		= 1;
	ctx->report_mbytes	= 0;
	ctx->page_size		= 4096;
	ctx->cache_line_size	= 64;
	ctx->num_of_qps		= 1;
	ctx->gid_index		= 0;
	ctx->sl			= 0;
	ctx->verb		= WRITE;

	if(to_parse)
	{
		if (parse(ctx,argc,argv))
		{
			exit(1);
		}
		ALLOCATE(ctx->qp,struct ibv_qp*,ctx->num_of_qps);
		ALLOCATE(ctx->my_addr,uintptr_t,ctx->num_of_qps);
	}
}

int copy_ctx(struct test_ctx *src, struct test_ctx *dest)
{

	init_ctx(dest, 0, NULL, 0);
	dest->port		= src->port;
	dest->ib_port		= src->ib_port;
	dest->size		= src->size;
	dest->mtu		= src->mtu;
	dest->inl		= src->inl;
	//GET_STRING(dest->ib_devname,strdupa(src->ib_devname));
	dest->iters		= src->iters;
	dest->duration		= src->duration;
	dest->margin		= src->margin;
	dest->processes		= src->processes;
	dest->tx_depth		= src->tx_depth;
	dest->rx_depth		= src->rx_depth;
	dest->page_size		= src->page_size;
	dest->cache_line_size	= src->cache_line_size;
	//dest->num_of_qps	= src->num_of_qps;
	dest->gid_index		= src->gid_index;
	dest->sl		= src->sl;
	dest->verb		= src->verb;

}

int init_test_data(struct test_ctx *ctx, test_data *data)
{
	int i;
	for (i = 0 ; i < ctx->num_of_qps; i++)
	{
		data[i].qp		= ctx->qp[i];
		data[i].qp_num		= ctx->qp[i]->qp_num;
		data[i].lid		= ctx->portinfo.lid;
		//data->gid		= 0;
		data[i].psn		= 0;
		data[i].rkey		= ctx->mr->rkey;
		data[i].srqn		= 0;
		data[i].vaddr		= (uintptr_t)ctx->my_addr[i];
		data[i].gid_index	= 0;
		data[i].mtu		= (int)ctx->mtu;
	}
	return 1;
}

void print_test_data(test_data *data)
{
	printf("qp=%d, qp_num=%d, lid=%x, psn=%d, rkey=%p, srqn=%d, vaddr=%p, gid_index=%d, mtu=%d\n",data->qp, data->qp_num, data->lid, data->psn, data->rkey, data->srqn, data->vaddr, data->gid_index, data->mtu);
}

static __inline void increase_loc_addr(struct ibv_sge *sg,int size,uint64_t rcnt,uint64_t prim_addr,int server_is_ud, int cache_line_size, int cycle_buffer)
{
        sg->addr  += INC(size,cache_line_size);
        if ( ((rcnt+1) % (cycle_buffer/ INC(size,cache_line_size))) == 0 )
                sg->addr = prim_addr;
}

static __inline void increase_exp_rem_addr(struct ibv_exp_send_wr *wr,int size,uint64_t scnt,uint64_t prim_addr,VerbType verb, int cache_line_size, int cycle_buffer)
{
	wr->wr.rdma.remote_addr += INC(size,cache_line_size);

	if ( ((scnt+1) % (cycle_buffer/ INC(size,cache_line_size))) == 0) {
		wr->wr.rdma.remote_addr = prim_addr;
	}
}

static int check_for_contig_pages_support(struct ibv_context *context)
{
        int answer;
        struct ibv_exp_device_attr attr;
        memset(&attr,0,sizeof attr);
        if (ibv_exp_query_device(context,&attr)) {
                fprintf(stderr, "Couldn't get device attributes\n");
                return 0;
        }
        answer = ( attr.exp_device_cap_flags &= IBV_EXP_DEVICE_MR_ALLOCATE) ? 1 : 0;
        return answer;
}

static int create_mr(struct test_ctx *ctx)
{
	struct ibv_exp_reg_mr_in reg_mr_exp_in;
	ctx->use_contig_pages = check_for_contig_pages_support(ctx->ctx);
	int i;

       	ctx->length = 2*BUFF_SIZE(ctx->size,ctx->page_size)*ctx->num_of_qps;
	ctx->addr = 0;

	if (!ctx->use_contig_pages)
	{
		ctx->addr = memalign(ctx->page_size,ctx->length);
       		if (!ctx->addr) {
       	        	fprintf(stderr, "failed to allocate memory\n");
	                return -1;
        	}
		memset(ctx->addr, 0,ctx->length);
		ctx->mr = ibv_reg_mr(ctx->pd, ctx->addr, ctx->length,
			IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);

	}
	else
	{
		reg_mr_exp_in.pd = ctx->pd;
		reg_mr_exp_in.addr = ctx->addr;
		reg_mr_exp_in.length = ctx->length;
		reg_mr_exp_in.exp_access = IBV_EXP_ACCESS_REMOTE_WRITE | IBV_EXP_ACCESS_LOCAL_WRITE | IBV_EXP_ACCESS_ALLOCATE_MR;
		reg_mr_exp_in.comp_mask = 0;

		ctx->mr = ibv_exp_reg_mr(&reg_mr_exp_in);
		if (ctx->mr == NULL)
		{
			fprintf(stderr, "failed to reg mr\n");
			return -1;
		}
		ctx->addr = ctx->mr->addr;
	}
	if (!ctx->mr) {
		fprintf(stderr, "failed to create mr\n");
		return -1;
	}

	for (i = 0; i < ctx->num_of_qps; i++)
	{
		ctx->my_addr[i] = (uintptr_t)ctx->addr + i*BUFF_SIZE(ctx->size, ctx->page_size);
	}

	return 0;
}

struct ibv_qp* ctx_qp_create(struct test_ctx *ctx)
{
	struct ibv_qp_init_attr attr;
	struct ibv_qp* qp = NULL;

	memset(&attr, 0, sizeof(struct ibv_qp_init_attr));
	attr.send_cq = ctx->cq;
	attr.recv_cq = ctx->cq;
	attr.cap.max_send_wr  = ctx->tx_depth;
	attr.cap.max_send_sge = 1;
	attr.cap.max_inline_data = ctx->inl;
	attr.srq = NULL;
	attr.cap.max_recv_wr  = ctx->rx_depth;
	attr.cap.max_recv_sge = 1;
	attr.qp_type = IBV_QPT_RC;

	qp = ibv_create_qp(ctx->pd,&attr);

	return qp;
}

int create_qps(struct test_ctx *ctx)
{
	int i;
	for (i = 0; i < ctx->num_of_qps; i++)
	{
		ctx->qp[i] = ctx_qp_create(ctx);
		if (!ctx->qp[i]) {
			printf("create qp failed\n");
			return -1;
		}

		struct ibv_qp_attr attr_init = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = ctx->ib_port,
			.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE,
		};

		if (ibv_modify_qp(ctx->qp[i], &attr_init,
			  IBV_QP_STATE              |
			  IBV_QP_PKEY_INDEX         |
			  IBV_QP_PORT               |
			  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			return -1;
		}

	}
	return 0;
}

void print_bw_report(struct test_ctx *ctx)
{
	printf("Iters = %ld , ",ctx->iters);
        float usec = (ctx->end.tv_sec - ctx->start.tv_sec) * 1000000 +
		(ctx->end.tv_usec - ctx->start.tv_usec);
	long long bytes = (long long) ctx->size * ctx->iters;

	float bw = (8*bytes)/(usec);

	if (ctx->report_mbytes)
		printf("BW = %.2f MB/s , ", (1000*1000*bw)/(1024*1024*8));
	else
		printf("BW = %.5f Gb/s , ", bw/(1000));

	printf("MR = %.5f Mpps\n", ctx->iters/(usec));

}
