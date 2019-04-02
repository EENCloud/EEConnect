/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_connection.h"
#include "pnp_dbus.h"

#include <gio/gio.h>

struct pnp_dbus_info {
	pthread_t pid;
	GMainLoop *gloop;
	GDBusNodeInfo *introspection_data;
	GDBusConnection *dbus;
	struct pnp_connection *pnp_conn;
};

static const gchar introspection_xml[] =
	"<node>"
	"    <interface name='nl.een.eeconnect'>"
	"      <method name='Reconnect'/>"
	"      <property type='b' name='Connected' access='read'/>"
	"      <signal name='Connected'/>"
	"      <signal name='Disconnected'/>"
	"    </interface>"
	"    <interface name='nl.een.eeconnect.Config'>"
	"      <property type='aa{sv}' name='dispatch' access='read'/>"
	"    </interface>"
	"</node>";

static GVariant *root_property_get(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *property_name,
		GError **error,
		gpointer user_data)
{
	GVariant *ret = NULL;
	struct pnp_dbus_info *info = user_data;
	struct pnp_connection *pnp_conn = info->pnp_conn;

	pnp_debug("%s %s", __FUNCTION__, property_name);

	if (g_strcmp0(property_name, "Connected") == 0) {
		ret = g_variant_new_boolean(pnp_conn->connection_state == PNP_CONNECTED ? true : false);
	}
	return ret;
}

static void root_method_call(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *method_name,
		GVariant *parameters,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct pnp_dbus_info *info = (struct pnp_dbus_info *)user_data;
	struct pnp_connection *pnp_conn = info->pnp_conn;

	g_message("method_call %s", method_name);

	if (g_strcmp0(method_name, "Reconnect") == 0) {
		if (pnp_conn && pnp_conn->loop_thread && pnp_conn->connection_state == PNP_CONNECTED) {
			pthread_kill(pnp_conn->loop_thread, SIGUSR1);
                        pnp_connection_set_state(pnp_conn, PNP_FORCE_RECONNECT);
		}
	}
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static const GDBusInterfaceVTable root_interface_vtable = {
	root_method_call,
	root_property_get,
	NULL,
};

static GVariant *get_dispatch_server(struct pnp_address *address)
{
	GVariantDict dict;
	GVariant *hostname = g_variant_new_string(address->hostname);
	GVariant *port = g_variant_new_uint16(atoi(address->port));

	g_variant_dict_init(&dict, NULL);

	g_variant_dict_insert_value(&dict, "hostname", hostname);
	g_variant_dict_insert_value(&dict, "port", port);

	return g_variant_dict_end(&dict);
}

static GVariant *get_dispatch_servers(struct pnp_server_addresses *sa)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init(&builder, G_VARIANT_TYPE_ARRAY);

	for (i = 0; i < sa->num; i++) {
		g_variant_builder_add_value(&builder,
					get_dispatch_server(sa->address[i]));
	}

	return g_variant_builder_end(&builder);
}

static GVariant *config_property_get(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *property_name,
				GError **error,
				gpointer user_data)
{
	struct pnp_dbus_info *info = user_data;
	struct pnp_configuration *conf = info->pnp_conn->conf;

	g_message("%s %s", __FUNCTION__, property_name);

	if (g_strcmp0(property_name, "dispatch") == 0)
		return get_dispatch_servers(&conf->sa);

	return NULL;
}

static const GDBusInterfaceVTable config_interface_vtable = {
	NULL,
	config_property_get,
	NULL,
};

static void on_bus_acquired(GDBusConnection *connection,
		const char *name,
		gpointer user_data)
{
	guint registration_id;
	struct pnp_dbus_info *info = (struct pnp_dbus_info *)user_data;

	pnp_info("DBus acquired %s", name);

	registration_id = g_dbus_connection_register_object(connection,
			"/",
			info->introspection_data->interfaces[0],
			&root_interface_vtable,
			user_data, NULL, NULL);
	g_assert(registration_id > 0);

	registration_id = g_dbus_connection_register_object(connection,
			"/",
			info->introspection_data->interfaces[1],
			&config_interface_vtable,
			user_data, NULL, NULL);
	g_assert(registration_id > 0);
}

static void dbus_main(struct pnp_dbus_info *info)
{
	guint owner_id;
	GError *err = NULL;
	GBusNameOwnerFlags flags = G_BUS_NAME_OWNER_FLAGS_NONE;

	g_assert(info->gloop);
	info->introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &err);
	g_assert(info->introspection_data != NULL);

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
			"nl.een.eeconnect",
			flags,
			on_bus_acquired,
			NULL,
			NULL,
			(gpointer)info,
			NULL);

	pnp_debug("Started GIO mainloop");
	g_main_loop_run(info->gloop);
	pnp_debug("Stopped GIO mainloop");

	g_bus_unown_name(owner_id);
	g_dbus_node_info_unref(info->introspection_data);
}

static void *dbus_thread(void *data)
{
	struct pnp_dbus_info *info = (struct pnp_dbus_info *)data;
	g_assert(info != NULL);
	info->gloop = g_main_loop_new(NULL, FALSE);
	if (!info->gloop) {
		pnp_err("Failed to create new main loop");
		g_main_loop_unref(info->gloop);
		return NULL;
	}
	dbus_main(info);
	g_main_loop_unref(info->gloop);
	return NULL;
}

int dbus_init(struct pnp_connection *pnp_conn)
{
	struct pnp_dbus_info *info;
	pnp_debug("dbus_init");

	if (pnp_conn->dbus != NULL) {
		pnp_err("pnp_connection->dbus is not NULL");
		return 0;
	}

	info = malloc(sizeof(*info));
	if (!info) {
		pnp_err("Cannot allocate memory for pnp_connection->dbus");
		return 0;
	}

	memset(info, 0x0, sizeof(*info));
	pnp_conn->dbus = info;
	info->pnp_conn = pnp_conn;

	return 1;
}

int dbus_start(struct pnp_dbus_info *info)
{
	pthread_attr_t attr;
	int ret;
	GError *err = NULL;

	pnp_debug("dbus_start");

	info->dbus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (info->dbus == NULL) {
		pnp_err("Failed to get DBus connection: %s", err->message);
		return 0;
	}

	ret = pthread_attr_init(&attr);
	if (ret) {
		pnp_err("Failed to initialize attr");
		return 0;
	}
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	ret = pthread_create(&info->pid, &attr, dbus_thread, (void *)info);
	if (ret) {
		pnp_err("Failed to create thread");
		pthread_attr_destroy(&attr);
		return 0;
	}
	pthread_attr_destroy(&attr);
	return 1;
}

void dbus_stop(struct pnp_dbus_info *info)
{
	pnp_debug("dbus_stop");
	g_assert(info != NULL);
	g_assert(info->dbus);
	g_dbus_connection_flush_sync(info->dbus, NULL, NULL);
	g_dbus_connection_close_sync(info->dbus, NULL, NULL);
	pnp_debug("Closing GIO mainloop");
	g_main_loop_quit(info->gloop);
	pnp_debug("Joining thread");
	pthread_join(info->pid, NULL);
	pnp_info("DBus finished");
}

void dbus_release(struct pnp_connection *pnp_conn)
{
	pnp_debug("dbus_release");
	pnp_conn->dbus = NULL;
	free(pnp_conn->dbus);
}

void dbus_connection_state_change(struct pnp_dbus_info *info, bool connected)
{
	g_assert(info);

	GError *err = NULL;
	if (info->dbus == NULL) {
		pnp_debug("DBus connection not ready");
		return;
	}
	g_dbus_connection_emit_signal(info->dbus,
			NULL,
			"/",
			"nl.een.eeconnect",
			connected ? "Connected" : "Disconnected",
			NULL,
			&err);
	if (err != NULL) {
		pnp_err("Failed to emit signal: %s", err->message);
		g_error_free(err);
	}
}

