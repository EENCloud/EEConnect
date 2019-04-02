/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_MAPPORT_H_
#define SRC_PNP_MAPPORT_H_

#include "pnp_common.h"

/* Macro definitions ------------------------------------------------------- */

#define PNP_MAPPORT_MAX_ITEMS 10

/* Type definitions -------------------------------------------------------- */

struct pnp_mapport_item {
	int port_in;
	int port_out;
};

struct pnp_mapport {
	int prefix;
	int camera_id_len;
	int port_len;
	int items_num;
	struct pnp_mapport_item items[PNP_MAPPORT_MAX_ITEMS];
};

/* Global functions -------------------------------------------------------- */

void pnp_mapport_init(struct pnp_mapport *mp);
bool pnp_mapport_add(struct pnp_mapport *mp, int port_in, int port_out);
bool pnp_mapport_set_prefix(struct pnp_mapport *mp, int prefix);
bool pnp_mapport_set_camera_id_len(struct pnp_mapport *mp, int camera_id_len);
bool pnp_mapport_set_port_len(struct pnp_mapport *mp, int port_len);
int pnp_mapport_get_in(struct pnp_mapport *mp, int index, const char *camera_serial);
int pnp_mapport_get_out(struct pnp_mapport *mp, int index);

#endif /* SRC_PNP_MAPPORT_H_ */
