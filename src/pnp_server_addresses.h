/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_SERVER_ADDRESSES_H_
#define SRC_PNP_SERVER_ADDRESSES_H_

#include "pnp_common.h"
#include "pnp_address.h"

/* Macro definitions ------------------------------------------------------- */

/* Type definitions -------------------------------------------------------- */

/*
 * @brief Information about servers addresses that we want to connect to
 */
struct pnp_server_addresses {
	struct pnp_address **address;
	int num;
};

/* Global functions -------------------------------------------------------- */

/* Create new object */
struct pnp_server_addresses* pnp_server_addresses_new(void);
void pnp_server_addresses_init(struct pnp_server_addresses *sa);

/* Add new addresses */
bool pnp_server_addresses_add
(struct pnp_server_addresses *sa, struct pnp_address *a);
bool pnp_server_addresses_add_ipv4_from_string
(struct pnp_server_addresses *sa, const char* address);
bool pnp_server_addresses_add_ip_port
(struct pnp_server_addresses *sa,
		const char *ip, int port);

/* Release resources */
void pnp_server_addresses_release(struct pnp_server_addresses *sa);
void pnp_server_addresses_empty(struct pnp_server_addresses *sa);

#endif /* SRC_PNP_SERVER_ADDRESSES_H_ */
