#
# Copyright (C) Mellanox Technologies Ltd. 2001-2011.  ALL RIGHTS RESERVED.
# This software product is a proprietary product of Mellanox Technologies Ltd.
# (the "Company") and all right, title, and interest and to the software product,
# including all associated intellectual property rights, are and shall
# remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
# $COPYRIGHT$
# $HEADER$
#

ACLOCAL_AMFLAGS= -I m4
AUTOMAKE_OPTIONS= subdir-objects

bin_PROGRAMS = rc_bw_server rc_bw_client xrc_bw_server xrc_bw_client dc_bw_server dc_bw_client
bin_SCRIPTS =

rc_bw_server_SOURCES = src/rc/rc_bw_server.c src/rc/common.h src/common_global.h -lpthread -lm
rc_bw_client_SOURCES = src/rc/rc_bw_client.c src/rc/common.h src/common_global.h -lpthread -lm
xrc_bw_server_SOURCES = src/xrc/xrc_bw_server.c src/xrc/common.h src/common_global.h -lpthread -lm
xrc_bw_client_SOURCES = src/xrc/xrc_bw_client.c src/xrc/common.h src/common_global.h -lpthread -lm
dc_bw_server_SOURCES = src/dc/dc_bw_server.c src/dc/common.h src/common_global.h -lpthread -lm
dc_bw_server_LDADD = -lmlx5
dc_bw_client_SOURCES = src/dc/dc_bw_client.c src/dc/common.h src/common_global.h -lpthread -lm
dc_bw_client_LDADD = -lmlx5

