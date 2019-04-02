/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CONNECTION_PROXY_H_
#define SRC_PNP_CONNECTION_PROXY_H_

#include "pnp_common.h"

/* Macro definitions ------------------------------------------------------- */

/* Type definitions -------------------------------------------------------- */

#include "pnp_connection_typedef.h"

/* Gobal functions --------------------------------------------------------- */

bool pnp_connection_proxy_init(struct pnp_connection_proxy *proxy,
		struct pnp_connection *c);

bool pnp_connection_proxy_close(struct pnp_connection_proxy *proxy);
bool pnp_connection_proxy_release(struct pnp_connection_proxy *proxy);
bool pnp_connection_proxy_server_start(struct pnp_connection_proxy_server *serv);
void pnp_connection_proxy_server_stop(struct pnp_connection_proxy_server *serv);

bool pnp_connection_start_proxy_servers(struct pnp_connection *c);
bool pnp_connection_stop_proxy_servers(struct pnp_connection *c);
bool pnp_connection_proxy_step(struct pnp_connection_proxy *proxy, fd_set *fds);
bool pnp_connection_proxy_server_step(struct pnp_connection_proxy_server *serv);
void pnp_connection_proxy_set_fds(struct pnp_connection_proxy *proxy,
		fd_set *fds, int *maxfd);

#endif /* SRC_PNP_CONNECTION_PROXY_H_ */
