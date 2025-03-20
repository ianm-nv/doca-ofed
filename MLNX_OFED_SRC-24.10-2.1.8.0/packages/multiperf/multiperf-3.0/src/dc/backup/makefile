all:
	gcc write/dc_write_bw_server.c -o dc_write_bw_server -lpthread -libverbs
	gcc write/dc_write_bw_client.c -o dc_write_bw_client -libverbs
	gcc read/dc_read_bw_server.c -o dc_read_bw_server -lpthread -libverbs
	gcc read/dc_read_bw_client.c -o dc_read_bw_client -libverbs
