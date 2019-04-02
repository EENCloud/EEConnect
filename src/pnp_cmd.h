/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CMD_H_
#define SRC_PNP_CMD_H_

#include "pnp_common.h"
#include "pnp_cmd_type.h"
#include "pnp_connection.h"

/* Macro definitions ------------------------------------------------------- */

/* Type definitions -------------------------------------------------------- */

/* Global functions -------------------------------------------------------- */

/* Send commands */
bool pnp_msg_send_ping(struct pnp_connection *c);
bool pnp_msg_send_hello(struct pnp_connection *c);
bool pnp_msg_send_redirect(struct pnp_connection *c, char *ip, char *port, int flags);
bool pnp_msg_send_data(struct pnp_connection *c,
		int channel_id, void *buffer, int buffer_len,
		int flags);
bool pnp_msg_send_closechannel(struct pnp_connection *c, int channel_id);
bool pnp_msg_send_openchannel(struct pnp_connection *c,
		int channel_id, char *ip, char *port);

/* Process received commands */
void pnp_cmd_client_process_cmds(struct pnp_connection *c);
void pnp_cmd_server_process_cmds(struct pnp_connection *c);

void pnp_cmd_client_process_cmds_step(struct pnp_connection *c);

#endif /* SRC_PNP_CMD_H_ */
