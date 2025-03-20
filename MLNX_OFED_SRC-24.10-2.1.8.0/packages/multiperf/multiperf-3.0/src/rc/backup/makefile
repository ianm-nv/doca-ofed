all:
	gcc write/rc_write_bw_server.c -o rc_write_bw_server -lpthread -libverbs
	gcc write/rc_write_bw_client.c -o rc_write_bw_client -libverbs
	gcc write/rc_read_bw_server.c -o rc_read_bw_server -lpthread -libverbs
	gcc write/rc_read_bw_client.c -o rc_read_bw_client -libverbs
