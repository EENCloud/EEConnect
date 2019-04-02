/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_ADDRESS_TYPEDEF_H_
#define SRC_PNP_ADDRESS_TYPEDEF_H_

/* Macro definitions ------------------------------------------------------- */

/* PnP address specific configuration */
#define PNP_HOSTNAME_MAXLEN 50
#define PNP_PORT_MAXLEN 8

/* Type definitions -------------------------------------------------------- */

/*
 * @brief Stores information about address (hostname:port)
 */
struct pnp_address {
	char hostname[PNP_HOSTNAME_MAXLEN + 1];
	char port[PNP_PORT_MAXLEN + 1];
};

#endif /* SRC_PNP_ADDRESS_TYPEDEF_H_ */
