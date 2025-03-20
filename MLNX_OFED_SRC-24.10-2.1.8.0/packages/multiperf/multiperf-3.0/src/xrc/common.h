#include <stdio.h>
#include <inttypes.h>
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
#include <math.h>
#include <infiniband/verbs.h>
#include "src/common_global.h"

#ifndef O_CREAT
#define O_CREAT	   0100
#endif

//#define MSG_FORMAT "000000:000000:000000:0000000000000000:0000000000000000:000000:0000000000000000:0000000000000000:00000000000000000000:000000:000000:0000"
//                   qp_num:tmp:lid:gid_h:gid_l:psn:num_of_srqs:gididx:mtu
#define MSG_FORMAT "%6x:%6x:%4x:%16"PRIx64":%16"PRIx64":%06x:%6"PRIx32":%06x:%04x"
//                   srq_num:rkey:vaddr
#define MSG_FORMAT_SRQ_NUMBER "%06x:%8"PRIx32":%16"PRIx64""

#define MSG_FORMAT_SIZE 80
#define MSG_SRQ_NUM_FORMAT_SIZE 33

#define PAGE_SIZE 4096
#define SRQ_UPPER_BOUND 1000
#define QP_UPPER_BOUND 10000

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

typedef enum {
	SEND, WRITE, READ, ATOMIC
} VerbType;

typedef enum {
	FETCH_AND_ADD, CMP_AND_SWAP
} AtomicType;

typedef struct data {
	struct ibv_qp *qp;
	int qp_num;
	int lid;
	int psn;
	unsigned rkey;
	uint64_t vaddr;
	union ibv_gid gid;
	unsigned srqn;
	int num_of_srqs;
	int gid_index;
	int mtu;
} test_data;

typedef struct {
	int *socket;
	test_data data;
	int tcp_port;
	int ib_port;
} handler_data;

typedef enum {
	START_STATE, SAMPLE_STATE, STOP_SAMPLE_STATE, END_STATE
} DurationStates;

struct test_ctx {
	struct ibv_qp **qps;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_mr **mrs;
	struct ibv_ah *ah;
	struct ibv_srq **srqs;
	struct ibv_xrcd *xrcd;
	struct ibv_context *ctx;
	void *addr;
	uintptr_t *my_addr;
	size_t length;
	int port;
	int tclass;
	union ibv_gid gid;
	unsigned size;
	int ib_port;
	enum ibv_mtu mtu;
	int user_mtu;
	struct ibv_port_attr portinfo;
	int inl;
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev;
	char *ib_devname;
	enum ctx_device device_name_by_id;
	uint64_t iters;
	int duration;
	int margin;
	DurationStates state;
	struct timeval start;
	struct timeval end;
	int use_event;
	char *servername;
	int processes;
	int tx_depth;
	int rx_depth;
	int report_mbytes;
	int num_of_qps;
	int upper_bound_total_qps;
	int num_of_srqs;
	int round_robin_srqs;
	uint32_t *srq_num_list;
	uint32_t *remote_rkey;  // size of srq_num
	uint64_t *remote_vaddr; // size of srq_num
	int page_size;
	int cache_line_size;
	VerbType verb;
	int gid_index;
	int sl;
	int use_contig_pages;
	int *socket;
	int out_reads;
	int cq_mod;
	int multiple_wr_client;
	int qp_timeout;
	int do_random_dest;
	int do_random_addr;
	int inl_recv;
	int mr_per_qp;
	int masked_atomics;
	AtomicType atomicType;
};

static inline int to_ib_mtu(int mtu, enum ibv_mtu *ibmtu) {
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

void usage(const char *argv0) {
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n",
			"rc_bw_server");
	printf("  %s <host>     connect to server at <host>\n", "rc_bw_client");
	printf("\n");
	printf("Options:\n");
	printf(
			"  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
	printf(
			"  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
	printf(
			"  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
	printf(
			"  -s, --size=<size>      size of message to exchange (default 65536)\n");
	printf("  -x, --gix=<gid_infex>  GID index to use\n");
	printf("  -m, --mtu              MTU size to use(default IBV_MTU_512)\n");
	printf("  -I, --inline           Requested inline size\n");
	printf("  -P, --processes        Number of processes to run (default 1)\n");
	printf("  -D, --duration         Set Duration value(default 3)\n");
	printf("  -f, --margin		 Set Margin value(default 0)\n");
	printf("  -t, --tx-depth         Set TX Depth value(default 128)\n");
	printf("  -h, --rx-depth         Set RX Depth value(default 128)\n");
	printf("  -q, --num_of_qps       Set Number of QPs to open(default 1)\n");
	printf("  -U, --upper_bound_total_qps       Upper bound for the total QPs which will connect the server (only relevant for the server) (default 10000)\n");
	printf("  -M  --report_mbytes    Report BW in MB/s units\n");
	printf("  -o  --outs		 Num of outstanding read (default 16)\n");
	printf("  -v  --verb		 Set Verb to use: WRITE / READ / SEND\n");
	printf("  -Q  --cq_mod		 Set CQ Mod value (default 100). this feature is disabled for -W (multiple_wr_per_qp)\n");
	printf("  -W  --multiple_wr_client		 set multiple wr per qp (only relevant for client) (default is single wr.)\n");
	printf("  -u  --qp_timeout	 Set QP Timeout (default 14)\n");
//	printf("  -R  --random=<size>	 Use Random addresses with MR #pages=<size>\n");
	printf("  -N  --num_of_srqs	 Num of srqs in the server side. (default 1)\n");
	printf("  -T  --tclass           traffic class\n");
	printf(
			"  -R  --round_robin_srqs      Use Round Robin srq destination per qp (default is random srq number per qp)\n");
	printf(
			"  -S  --random_mem       Use Random addresses inside memory region\n");

	printf("\n");
}

int parse(struct test_ctx *ctx, int argc, char *argv[]) {
	srand48(getpid() * time(NULL));
	int mtu, size_factor = 1, size_len;
	char *verb, *atomicType;

	while (1) {
		int c;

		static struct option long_options[] = { { .name = "port", .has_arg = 1,
				.val = 'p' }, { .name = "ib-dev", .has_arg = 1, .val = 'd' }, {
				.name = "ib-port", .has_arg = 1, .val = 'i' }, { .name = "size",
				.has_arg = 1, .val = 's' }, { .name = "gix", .has_arg = 1,
				.val = 'x' }, { .name = "mtu", .has_arg = 1, .val = 'm' }, {
				.name = "inline", .has_arg = 1, .val = 'I' }, {
				.name = "processes", .has_arg = 1, .val = 'P' }, { .name =
				"duration", .has_arg = 1, .val = 'D' }, { .name = "margin",
				.has_arg = 1, .val = 'f' }, { .name = "tx-depth", .has_arg = 1,
				.val = 't' }, { .name = "rx-depth", .has_arg = 1,.val = 'h' },
				{ .name = "num_of_qps", .has_arg = 1, .val = 'q' }, { .name =
						"num_of_srqs", .has_arg = 1, .val = 'N' }, { .name =
								"upper_bound_total_qps", .has_arg = 1, .val = 'U' }, { .name =
						"report_mbytes", .has_arg = 0, .val = 'M' }, { .name =
						"round_robin", .has_arg = 0, .val = 'R' }, { .name =
						"mr_per_qp", .has_arg = 0, .val = 'L' }, { .name =
						"outs", .has_arg = 1, .val = 'o' }, { .name = "verb",
						.has_arg = 1, .val = 'v' }, { .name = "cq_mod",
						.has_arg = 1, .val = 'Q' }, { .name = "multiple_wr_client",
								.has_arg = 0, .val = 'W' }, { .name = "qp_timeout",
						.has_arg = 1, .val = 'u' }, { .name = "tclass",
						.has_arg = 1, .val = 'T' }, { .name = "random_mem",
						.has_arg = 0, .val = 'S' },

				{ .name = "atomic_type", .has_arg = 1, .val = 'A' }, { 0 } };

		c = getopt_long(argc, argv,
				"p:d:i:s:x:m:I:P:D:t:h:f:q:N:U:o:v:Q:u:S:A:T:MRLWS", long_options,
				NULL);
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
			GET_STRING(ctx->ib_devname, strdup(optarg))
			;
			break;

		case 'v':
			GET_STRING(verb, strdup(optarg))
			;
			if (!strcmp(verb, "WRITE"))
				ctx->verb = WRITE;
			else if (!strcmp(verb, "READ"))
				ctx->verb = READ;
			else if (!strcmp(verb, "ATOMIC"))
				ctx->verb = ATOMIC;
			else if (!strcmp(verb, "SEND"))
				ctx->verb = SEND;
			else {
				fprintf(stderr, "invalid verb selection\n\n");
				usage(argv[0]);
				return 1;
			}
			break;

		case 'A':
			GET_STRING(atomicType, strdup(optarg))
			;
			if (!strcmp(atomicType, "CMP_AND_SWAP"))
				ctx->atomicType = CMP_AND_SWAP;
			else if (!strcmp(atomicType, "FETCH_AND_ADD"))
				ctx->atomicType = FETCH_AND_ADD;
			else {
				fprintf(stderr, "invalid ATOMIC type selection\n\n");
				usage(argv[0]);
				return 1;
			}
			break;

		case 'I':
			ctx->inl = strtol(optarg, NULL, 0);
			if (ctx->inl < 0) {
				usage(argv[0]);
				return 1;
			}
			break;

		case 'S':
			ctx->inl_recv = strtol(optarg, NULL, 0);
			if (ctx->inl_recv < 0) {
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
			ctx->user_mtu = 1;
			if (to_ib_mtu(mtu, &ctx->mtu)) {
				printf("invalid MTU %d\n", mtu);
				return 1;
			}
			break;

		case 's':
			size_len = (int) strlen(optarg);
			if (optarg[size_len - 1] == 'K') {
				optarg[size_len - 1] = '\0';
				size_factor = 1024;
			}
			if (optarg[size_len - 1] == 'M') {
				optarg[size_len - 1] = '\0';
				size_factor = 1024 * 1024;
			}
			ctx->size = (uint64_t) strtol(optarg, NULL, 0) * size_factor;
			if (ctx->size < 1 || ctx->size > (UINT_MAX / 2)) {
				fprintf(stderr, " Message Size should be between %d and %d\n",
						1, UINT_MAX / 2);
				return 1;
			}
			break;

		case 'x':
			ctx->gid_index = strtoull(optarg, NULL, 0);
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

		case 'o':
			ctx->out_reads = strtol(optarg, NULL, 0);
			break;

		case 't':
			ctx->tx_depth = strtol(optarg, NULL, 0);
			break;

		case 'h':
			ctx->rx_depth = strtol(optarg, NULL, 0);
			break;

		case 'u':
			ctx->qp_timeout = strtol(optarg, NULL, 0);
			break;

		case 'T':
			ctx->tclass = strtol(optarg, NULL, 0);
			break;

		case 'Q':
			CHECK_VALUE(ctx->cq_mod, int, 1, 1024, "CQ moderation")
			;
			break;

		case 'W':
			ctx->multiple_wr_client = 1;
			break;

		case 'q':
			ctx->num_of_qps = strtol(optarg, NULL, 0);
			break;

		case 'N':
			ctx->num_of_srqs = strtol(optarg, NULL, 0);
			break;

		case 'U':
			ctx->upper_bound_total_qps = strtol(optarg, NULL, 0);
			break;

		case 'M':
			ctx->report_mbytes = 1;
			break;

		case 'L':
			ctx->mr_per_qp = 1;
			break;

		case 'R':
			ctx->round_robin_srqs = 1;
			break;

		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind == argc - 1) {
		GET_STRING(ctx->servername, strdup(argv[optind]));
	} else if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	return 0;
}

void copy_test_data(test_data *src, test_data *dest) {
	dest->qp = src->qp;
	dest->qp_num = src->qp_num;
	dest->lid = src->lid;
	dest->gid = src->gid;
	dest->psn = src->psn;
	dest->rkey = src->rkey;
	dest->srqn = 0;
	dest->vaddr = src->vaddr;
	dest->gid_index = src->gid_index;
	dest->mtu = src->mtu;
}

int init_ctx(struct test_ctx *ctx, int argc, char *argv[], int to_parse) {
	ctx->port = 18515;
	ctx->ib_port = 1;
	ctx->size = 65536;
	ctx->mtu = IBV_MTU_512;
	ctx->user_mtu = 0;
	ctx->inl = 0;
	ctx->ib_devname = NULL;
	ctx->iters = 10000;
	ctx->duration = 3;
	ctx->margin = 0;
	ctx->processes = 1;
	ctx->tx_depth = 128;
	ctx->rx_depth = 128;
	ctx->report_mbytes = 0;
	ctx->page_size = 4096;
	ctx->cache_line_size = 64;
	ctx->num_of_qps = 1;
	ctx->upper_bound_total_qps = QP_UPPER_BOUND;
	ctx->num_of_srqs = 1;
	ctx->gid_index = 3;
	ctx->sl = 0;
	ctx->out_reads = 16;
	ctx->cq_mod = 100;
	ctx->multiple_wr_client = 0;
	ctx->qp_timeout = 14;
	ctx->do_random_addr = 0;
	ctx->do_random_dest = 0;
	ctx->inl_recv = 0;
	ctx->mr_per_qp = 0;
	ctx->round_robin_srqs = 0;
	ctx->verb = WRITE;
	ctx->masked_atomics = 0;
	ctx->atomicType = FETCH_AND_ADD;

	if (to_parse) {
		if (parse(ctx, argc, argv)) {
			exit(1);
		}

		if (ctx->inl != 0 && ctx->verb == READ) {
			fprintf(stderr, "Inline is not supported in READ\n");
			ctx->inl = 0;
		}

		if (ctx->cq_mod > ctx->tx_depth) {
			ctx->cq_mod = ctx->tx_depth;
			fprintf(stderr, "Setting cq_mod = %d\n", ctx->cq_mod);
		}

		if (ctx->do_random_addr) {
			ctx->page_size = 2 * PAGE_SIZE * ctx->do_random_addr;
		}

		if (ctx->verb == ATOMIC) {
			ctx->size = 8;
		}

	}

	return 0;
}

int copy_ctx(struct test_ctx *src, struct test_ctx *dest) {

	init_ctx(dest, 0, NULL, 0);
	dest->cq = src->cq;
	dest->pd = src->pd;
	dest->mrs = src->mrs;
	dest->ah = src->ah;
	dest->srqs = src->srqs;
	dest->xrcd = src->xrcd;
	dest->ctx = src->ctx;
	dest->addr = src->addr;
	dest->my_addr = src->my_addr;
	dest->length = src->length;
	dest->port = src->port;
	dest->tclass = src->tclass;
	dest->gid = src->gid;
	dest->size = src->size;
	dest->ib_port = src->ib_port;
	dest->mtu = src->mtu;
	dest->user_mtu = src->user_mtu;
	dest->portinfo = src->portinfo;
	dest->inl = src->inl;
	if (src->ib_devname != NULL)
		GET_STRING(dest->ib_devname, strdup(src->ib_devname));
	dest->iters = src->iters;
	dest->duration = src->duration;
	dest->margin = src->margin;
	dest->state = src->state;
	dest->start = src->start;
	dest->end = src->end;
	dest->use_event = src->use_event;
	dest->processes = src->processes;
	dest->tx_depth = src->tx_depth;
	dest->rx_depth = src->rx_depth;
	dest->report_mbytes = src->report_mbytes;
	dest->num_of_qps = src->num_of_qps;
	dest->num_of_srqs = src->num_of_srqs;
	dest->round_robin_srqs = src->round_robin_srqs;
	dest->upper_bound_total_qps = src->upper_bound_total_qps;
	dest->srq_num_list = src->srq_num_list;
	dest->remote_rkey = src->remote_rkey;
	dest->remote_vaddr = src->remote_vaddr;
	dest->page_size = src->page_size;
	dest->cache_line_size = src->cache_line_size;
	dest->verb = src->verb;
	dest->gid_index = src->gid_index;
	dest->sl = src->sl;
	dest->use_contig_pages = src->use_contig_pages;
	dest->socket = src->socket;
	dest->out_reads = src->out_reads;
	dest->cq_mod = src->cq_mod;
	dest->multiple_wr_client = src->multiple_wr_client;
	dest->qp_timeout = src->qp_timeout;
	dest->do_random_dest = src->do_random_dest;
	dest->do_random_addr = src->do_random_addr;
	dest->inl_recv = src->inl_recv;
	dest->mr_per_qp = src->mr_per_qp;
	dest->masked_atomics = src->masked_atomics;
	dest->atomicType = src->atomicType;
	return 0;
}

int init_test_data(struct test_ctx *ctx, test_data *data) {
	int i;
	for (i = 0; i < ctx->num_of_qps; i++) {
		data[i].qp = ctx->qps[i];
		data[i].qp_num = ctx->qps[i]->qp_num;
		data[i].lid = ctx->portinfo.lid;
		data[i].gid = ctx->gid;
		data[i].psn = 0;
		data[i].rkey = ctx->mrs[i]->rkey;
		data[i].srqn = 0;
		data[i].vaddr = (uintptr_t) ctx->my_addr[i];
		data[i].gid_index = ctx->gid_index;
		data[i].mtu = (int) ctx->mtu;
	}
	return 1;
}

void print_test_data(test_data *data) {
	printf(
			"qp=%p, qp_num=%d, lid=%x, psn=%d, rkey=%x, srqn=%d, vaddr=%p, gid_index=%d, mtu=%d\n",
			(void *) data->qp, data->qp_num, data->lid, data->psn, data->rkey,
			data->srqn, (void *) data->vaddr, data->gid_index, data->mtu);
}

static __inline void increase_loc_addr(struct ibv_sge *sg, int size,
		uint64_t rcnt, uint64_t prim_addr, int server_is_ud,
		int cache_line_size, int cycle_buffer) {
	sg->addr += INC(size, cache_line_size);
	if (((rcnt + 1) % (cycle_buffer / INC(size, cache_line_size))) == 0)
		sg->addr = prim_addr;
}

static __inline void increase_rem_addr(struct ibv_send_wr *wr, int size,
		uint64_t scnt, uint64_t prim_addr, VerbType verb, int cache_line_size,
		int cycle_buffer) {
	wr->wr.rdma.remote_addr += INC(size, cache_line_size);

	if (((scnt + 1) % (cycle_buffer / INC(size, cache_line_size))) == 0) {
		wr->wr.rdma.remote_addr = prim_addr;
	}
}

static __inline void increase_rand_loc_addr(struct ibv_sge *sg, int size,
		uint64_t rcnt, uint64_t prim_addr, int server_is_ud,
		int cache_line_size, int cycle_buffer, int n) {
	int steps = n % (cycle_buffer / INC(size, cache_line_size));
	sg->addr = prim_addr + steps * INC(size, cache_line_size);
}

static __inline void increase_rand_rem_addr(struct ibv_send_wr *wr,
		int size, uint64_t scnt, uint64_t prim_addr, VerbType verb,
		int cache_line_size, int cycle_buffer, int n) {
	int steps = n % (cycle_buffer / INC(size, cache_line_size));
	wr->wr.rdma.remote_addr = prim_addr + steps * INC(size, cache_line_size);
}

int create_single_mr(struct test_ctx *ctx, int i) {
	ctx->addr = memalign(ctx->page_size, ctx->length);
	if (!ctx->addr) {
		fprintf(stderr, "failed to allocate memory\n");
		return 1;
	}
	memset(ctx->addr, 0, ctx->length);

	ctx->mrs[i] = ibv_reg_mr(ctx->pd, ctx->addr, ctx->length,
			IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE
					| IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);

	if (!ctx->mrs[i]) {
		fprintf(stderr, "failed to create mrs[%d]\n", i);
		return 1;
	}

	return 0;
}

int create_mr(struct test_ctx *ctx) {
	int i;

	if (ctx->mr_per_qp)
		ctx->length = 2 * BUFF_SIZE(ctx->size, ctx->page_size);
	else
		ctx->length = 2 * BUFF_SIZE(ctx->size, ctx->page_size)
				* ctx->num_of_qps;
	/* create first MR */
	if (create_single_mr(ctx, 0)) {
		fprintf(stderr, "failed to create single mr\n");
		return 1;
	}
	ctx->my_addr[0] = (uintptr_t) ctx->mrs[0]->addr;

	for (i = 1; i < ctx->num_of_qps; i++) {
		if (ctx->mr_per_qp) {
			if (create_single_mr(ctx, i)) {
				fprintf(stderr, "failed to create single mrs[%d]\n", i);
				return 1;
			}

			ctx->my_addr[i] = (uintptr_t) ctx->mrs[i]->addr;
		} else {
			ALLOCATE(ctx->mrs[i], struct ibv_mr, 1);
			memset(ctx->mrs[i], 0, sizeof(struct ibv_mr));
		ctx->mrs[i] = ctx->mrs[0];
		ctx->my_addr[i] = (uintptr_t) ctx->mrs[0]->addr
				+ i * BUFF_SIZE(ctx->size, ctx->page_size);
		}
	}

	return 0;
}

void print_bw_report(struct test_ctx *ctx) {
	printf("Process %d:    Iters = %ld ,", getpid(), ctx->iters);
	float usec = (ctx->end.tv_sec - ctx->start.tv_sec) * 1000000
			+ (ctx->end.tv_usec - ctx->start.tv_usec);
	long long bytes = (long long) ctx->size * ctx->iters;
	float bw = (8 * bytes) / (usec);

	if (ctx->report_mbytes)
		printf("BW = %.2f MB/s , ", (1000 * 1000 * bw) / (1024 * 1024 * 8));
	else
		printf("BW = %.5f Gb/s , ", bw / (1000));

	printf("MR = %.5f Mpps\n", ctx->iters / (usec));

}