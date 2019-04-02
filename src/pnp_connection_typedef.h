/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CONNECTION_TYPEDEF_H_
#define SRC_PNP_CONNECTION_TYPEDEF_H_

#include "pnp_connection_state.h"
#include "pnp_address_typedef.h"

#include "pnp_configuration.h"
#include "pnp_channel.h"
#include "pnp_buffer.h"
#include "pnp_dbus.h"

/* Macro definitions ------------------------------------------------------- */

#define PNP_CONNECTION_PROXY_SERVERS 10

/* Type definitions -------------------------------------------------------- */

/*
 * @brief Structure that has information about single proxy server (listener)
 */
struct pnp_connection_proxy_server {
	int listen_fd;
	int af;

	pthread_t thread_id;
	pthread_mutex_t mutex;
	enum pnp_thread_state state;

	int port_in;
	int port_out;

	void *c;
};

/*
 * @brief Structure that has information about proxy servers
 */
struct pnp_connection_proxy {
	struct pnp_connection_proxy_server server[PNP_CONNECTION_PROXY_SERVERS];
};

/*
 * @brief Structure that has all information about connection
 */
struct pnp_connection {
	enum pnp_connection_state connection_state;
	int socket_fd;
	struct pnp_address *redirect_address; /* Should be released explicitly
	 before closing connection */
	struct pnp_channel_container ch_con;
	struct pnp_connection_proxy proxy;

	struct pnp_configuration *conf;

	struct pnp_io *io;
	void *io_data;

	struct pnp_buffer rbuf;
	struct pnp_buffer wbuf;

	bool cmd_continue;
	uint8_t cmd;

	bool process_cmds_continue;

	bool server_mode;

	pthread_t loop_thread;

	time_t last_ping;
	time_t last_in;
	time_t last_out;

	struct timespec pselect_ts;

	struct pnp_dbus_info *dbus;
};

#endif /* SRC_PNP_CONNECTION_TYPEDEF_H_ */
