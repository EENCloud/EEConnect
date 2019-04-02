/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include "client_config.h"

#define CLIENT_CONF       "client.json"
#define CLIENT_CONF_PATH  CONFIG_DIR "/" CLIENT_CONF

using namespace std;
using namespace rapidjson;

static void add_address(struct pnp_server_addresses *sa, Value &address)
{
	const char *hostname = address["hostname"].GetString();
	const int port = address["port"].GetInt();

	if (pnp_server_addresses_add_ip_port(sa, hostname, port)) {
		pnp_info("add address: %s : %d", hostname, port);
	} else {
		pnp_err("Refusing to add invalid address: %s %d !!",
			hostname, port);
	}
}

bool client_config_load(struct pnp_configuration *conf)
{
	struct pnp_file json_conf;
	Document config;
	int err;

	err = pnp_file_load(&json_conf, CLIENT_CONF, CLIENT_CONF_PATH);
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
		Value &dispatch = config["dispatch"];
		for (unsigned int i = 0; i < dispatch.Size(); i++) {
			Value &address = dispatch[i];
			add_address(&conf->sa, address);
		}
		return true;
	} catch (string &out) {
		pnp_err("Exception: %s", out.c_str());
	} catch (...) {
		pnp_err("Unknown error");
	}

	return false;
}
