/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_mapport.h"

/*
 * Port number generation: [prefix][camera_id][port], where:
 * camera_id is camera_id_len characters long
 * port is port_len characters long
 */

static int ipow(int a, int x)
{
	int ret = 1;
	int i;

	for (i = 0; i < x; i++) {
		ret *= a;
	}
	return ret;
}

void pnp_mapport_init(struct pnp_mapport *mp)
{
	mp->prefix = 3;
	mp->camera_id_len = 3;
	mp->port_len = 1;
	mp->items_num = 0;
}

bool pnp_mapport_add(struct pnp_mapport *mp, int port_in, int port_out)
{
	mp->items[mp->items_num].port_in = port_in;
	mp->items[mp->items_num].port_out = port_out;

	mp->items_num++;
	return true;
}

bool pnp_mapport_set_prefix(struct pnp_mapport *mp, int prefix)
{
	mp->prefix = prefix;
	return true;
}

bool pnp_mapport_set_camera_id_len(struct pnp_mapport *mp, int camera_id_len)
{
	mp->camera_id_len = camera_id_len;
	return true;
}

bool pnp_mapport_set_port_len(struct pnp_mapport *mp, int port_len)
{
	mp->port_len = port_len;
	return true;
}

int pnp_mapport_get_in(struct pnp_mapport *mp, int index, const char *camera_serial)
{
	int port;
	int tmp;
	int i;
	int camera_id = atoi(camera_serial);

	port = mp->items[index].port_in;

	tmp = (camera_id >= 0 ? camera_id : -camera_id) % ipow(10, mp->camera_id_len);
	for (i = 0; i < mp->port_len; i++)
		tmp *= 10;
	port += tmp;

	tmp = mp->prefix;
	for (i = 0; i < mp->port_len + mp->camera_id_len; i++)
		tmp *= 10;
	port += tmp;

	return port;
}

int pnp_mapport_get_out(struct pnp_mapport *mp, int index)
{
	return mp->items[index].port_out;
}
