/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CHANNEL_H_
#define SRC_PNP_CHANNEL_H_

#include "pnp_common.h"
#include "pnp_connection_state.h"
#include "pnp_thread_helper.h"
#include "pnp_buffer.h"

#include <pthread.h>

/* Macro definitions ------------------------------------------------------- */
#define PNP_CHANNEL_CONTAINER_TABLE_SIZE 256

/* Type definitions -------------------------------------------------------- */

struct pnp_connection;

struct pnp_channel {
	int channel_id;

	int socket_fd;

	enum pnp_connection_state connection_state;

	bool shutdown;

	struct pnp_buffer rbuf;
	struct pnp_buffer wbuf;

	struct pnp_connection *c;

	bool closed_ext;
	bool closed_int;

#ifdef PNP_DEBUG
int debug_data_out_id;
int debug_data_in_id;
#endif
};

struct pnp_channel_container {
	struct pnp_channel *table[PNP_CHANNEL_CONTAINER_TABLE_SIZE];
	int channel_idx;
};

/* Global functions -------------------------------------------------------- */

/* Creation and initialization of channel info */
struct pnp_channel* pnp_channel_new(struct pnp_connection *c);
struct pnp_channel* pnp_channel_new_with_id(struct pnp_connection *c,
					int channel_id);

/* Closing and releasing channel resources */
void pnp_channel_close(struct pnp_channel *ch);
void pnp_channel_release(struct pnp_channel *ch);

bool pnp_channel_connect_to(struct pnp_channel *ch, char *ip, int i_port);
void pnp_channel_set_fds(struct pnp_channel *ch, fd_set *r_fds, fd_set *w_fds,
	int *maxfd);
void pnp_channel_step(struct pnp_channel *ch, fd_set *r_fds, fd_set *w_fds);
bool pnp_channel_read_step(struct pnp_channel *ch, fd_set *r_fds);
bool pnp_channel_write_step(struct pnp_channel *ch, fd_set *w_fds);

/* Creation and releasing resources for channel container */
struct pnp_channel_container* pnp_channel_container_new(void);
bool pnp_channel_container_init(struct pnp_channel_container *ch_con);
void pnp_channel_container_destroy(struct pnp_channel_container *ch_con);
void pnp_channel_container_empty(struct pnp_channel_container *ch_con);
void pnp_channel_container_release(struct pnp_channel_container *ch_con);
void pnp_channel_container_set_fds(struct pnp_channel_container *ch_con,
	fd_set *r_fds, fd_set *w_fds, int *maxfd);

/* Managing connections within channel container */
bool pnp_channel_container_add(struct pnp_channel_container *ch_con,
			struct pnp_connection *c,
			int *channel_id, char *ip, int i_port_socket);
bool pnp_channel_container_remove(struct pnp_channel_container *ch_con,
	int channel_id);

#endif /* SRC_PNP_CHANNEL_H_ */
