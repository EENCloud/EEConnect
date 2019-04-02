/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "server_config.h"

#include <cstdio>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#define SERVER_CONF       "server.json"
#define SERVER_CONF_PATH  CONFIG_DIR "/" SERVER_CONF

using namespace std;
using namespace rapidjson;

bool server_config_load(struct pnp_configuration *conf)
{
	struct pnp_file json_conf;
	Document config;
	int err;

	err = pnp_file_load(&json_conf, SERVER_CONF, SERVER_CONF_PATH);
	if (err) {
		pnp_err("No json data available");
		return false;
	}

	pnp_info("Parsing json string");
	config.Parse<kParseDefaultFlags>(pnp_file_get_content(&json_conf));
	pnp_file_release(&json_conf);

	if (config.HasParseError()) {
		pnp_err("Json string has parse error: %d %s",
				config.GetParseError(),
				GetParseError_En(config.GetParseError()));
		return false;
	}

	pnp_info("Parsing done, document type: %d", config.GetType());

	try {
		if (config.HasMember("mapPorts")) {
			Value &map = config["mapPorts"];

			pnp_mapport_set_camera_id_len(&conf->mp, map["cameraIdLen"].GetInt());
			pnp_info("camera_id_len: %d", conf->mp.camera_id_len);

			pnp_mapport_set_port_len(&conf->mp, map["portLen"].GetInt());
			pnp_info("port_len: %d", conf->mp.port_len);

			pnp_mapport_set_prefix(&conf->mp, map["prefix"].GetInt());
			pnp_info("prefix: %d", conf->mp.prefix);

			Value &ports = map["ports"];
			for (unsigned int i = 0; i < ports.Size(); i++) {
				Value &port = ports[i];
				pnp_mapport_add(&conf->mp, port["in"].GetInt(), port["out"].GetInt());
				pnp_info("port: %d -> %d",
						conf->mp.items[i].port_in,
						conf->mp.items[i].port_out);
			}
		}
		return true;
	} catch (string &out) {
		pnp_err("Exception: %s", out.c_str());
	} catch (...) {
		pnp_err("Unknown error");
	}

	return false;
}
