/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CONNECTION_H_
#define SRC_PNP_CONNECTION_H_

#include "pnp_address.h"
#include "pnp_channel.h"
#include "pnp_common.h"
#include "pnp_configuration.h"
#include "pnp_connection_proxy.h"
#include "pnp_connection_state.h"
#include "pnp_connection_typedef.h"
#include "pnp_io.h"
#include "pnp_thread_helper.h"

/* Creation and initialization of connection info */

struct pnp_connection* pnp_connection_new(void);
bool pnp_connection_init(struct pnp_connection *c,
			struct pnp_configuration *conf);

/* Closing and releasing connection resources */
void pnp_connection_close(struct pnp_connection *c);
void pnp_connection_release(struct pnp_connection *c);

/* Accept connection from client */
int pnp_connection_accept(struct pnp_connection **c,
			int listen_fd, int af,
			struct pnp_configuration *conf,
			pnp_io_setup_t setup_io, void *io_data);

/* Connection to server */
bool pnp_connection_connect(struct pnp_connection *c, struct pnp_address *a);

/* Loop used for processing PnP connection data */
void pnp_connection_loop(struct pnp_connection *c);

static inline void pnp_connection_set_state(struct pnp_connection *c,
					enum pnp_connection_state state)
{
	c->connection_state = state;
}

int pnp_connection_wait_for_data(struct pnp_connection *c,
				struct timespec *timestamp,
				bool write);

static inline void pnp_connection_setup_io(struct pnp_connection *c,
					struct pnp_io *io, void *io_data)
{
	c->io = io;
	c->io_data = io_data;
}

static inline void *pnp_connection_io_data(struct pnp_connection *c)
{
	return c->io_data;
}

#endif /* SRC_PNP_CONNECTION_H_ */
