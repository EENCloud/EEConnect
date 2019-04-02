/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CONFIGURATION_H_
#define SRC_PNP_CONFIGURATION_H_

#include "pnp_common.h"
#include "pnp_server_addresses.h"
#include "pnp_mapport.h"

/* Macro definitions ------------------------------------------------------- */

#define PNP_SERIAL_SIZE 32
#define PNP_SECRET_SIZE 32

/* Type definitions -------------------------------------------------------- */
struct pnp_file {
	char *data;
	bool freeable;
};

struct pnp_configuration {
	struct pnp_mapport mp;
	struct pnp_server_addresses sa;
	char serial[PNP_SERIAL_SIZE + 1];
	int ping_send_period;
	int pnp_socket_timeout;
	int reconnect_wait;
	int retry_wait;
	int connect_timeout;
	int ssl_negotiation_maxtime;
};

/* Global functions -------------------------------------------------------- */

void pnp_configuration_init(struct pnp_configuration *conf);
int pnp_file_load(struct pnp_file *file, const char *structure_name,
		const char *file_name);
void pnp_file_release(struct pnp_file *file);
static inline char *pnp_file_get_content(struct pnp_file *file)
{
	return file->data;
}
void pnp_configuration_deinit(struct pnp_configuration *conf);

#endif /* SRC_PNP_CONFIGURATION_H_ */
