/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_ADDRESS_H_
#define SRC_PNP_ADDRESS_H_

#include "pnp_common.h"

#include <stdint.h>

/* Macro definitions ------------------------------------------------------- */

#define PNP_DEFAULT_PORT "80"

/* Type definitions -------------------------------------------------------- */

#include "pnp_address_typedef.h"

/* Global functions -------------------------------------------------------- */

/* Create new object */
struct pnp_address* pnp_address_new_ipv4(const char *address);
struct pnp_address* pnp_address_new_ip_port(const char* ip, int32_t port);
struct pnp_address* pnp_address_new_hostname_port(const char *hostname,
		const char *port);

/* Release resources */
void pnp_address_release(struct pnp_address *a);

#endif /* SRC_PNP_ADDRESS_H_ */
