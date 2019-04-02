/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_DBUS_H_
#define SRC_PNP_DBUS_H_

struct pnp_connection;
struct pnp_dbus_info;

#ifdef DBUS_ENABLED

int dbus_init(struct pnp_connection *pnp_conn);
int dbus_start(struct pnp_dbus_info *info);
void dbus_stop(struct pnp_dbus_info *info);
void dbus_release(struct pnp_connection *pnp_conn);
void dbus_connection_state_change(struct pnp_dbus_info *info, bool state);

#else /* DBUS_ENABLED */

static inline int dbus_init(struct pnp_connection *pnp_conn)
{
	return 1;
}
static inline int dbus_start(struct pnp_dbus_info *info)
{
	return 1;
}
#define dbus_release(...)
#define dbus_stop(...)
#define dbus_connection_state_change(...)

#endif /* DBUS_ENABLED */

#endif /* SRC_PNP_DBUS_H_ */
