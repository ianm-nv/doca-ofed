date: 05/08/18
By: Ido Tulman
Name: XRC BW

Run a server:
./xrc_bw_server -d <device> -p <port number> -v <verb> -N <num_of_srqs> -U <upper_qp_bound> etc...
example:
./xrc_bw_server -d mlx5_0 -p 20001 -v SEND -N 20 -U 10000

Run a client:
./xrc_bw_client <server> -d <device> -p <port number> -v <verb> -N <num_of_srqs> -q <num_of_qps> -D <duration> -P <processes> etc...
example:
./xrc_bw_client clx-app-008 -d mlx5_0 -p 20001 -v SEND -N 20 -q 10 -D 1

Important client Flags:

-W:  multiple_wr_client.  set multiple wr per qp (default is single wr.)  in this mode, for each qp their will be linked list of WR's.
-R:  round-robin.         each qp's WR will choose the srq with round-robin (default is random).
-t:  tx_depth. 			Note: make sure rx_depth on server side >= tx_depth on client side. It's important for getting enough post_recv_srq...