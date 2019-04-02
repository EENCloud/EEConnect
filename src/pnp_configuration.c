/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_configuration.h"

#include <stdio.h>
#include <sys/stat.h>
#include "embed.h"

static char *pnp_file_read(const char *file_name)
{
	FILE *fp = fopen(file_name, "rb");
	struct stat st;
	long file_size;
	char *buf = NULL;

	if (!fp)
		return NULL;

	if (stat(file_name, &st) != 0)
		goto close_file;

	file_size = st.st_size;
	buf = malloc(file_size + 1);
	if (!buf)
		goto close_file;

	if ((long)fread(buf, 1, file_size, fp) < file_size)
		goto close_file;

	buf[file_size] = '\0';

close_file:
	fclose(fp);
	return buf;
}

int pnp_file_load(struct pnp_file *file, const char *structure_name,
		const char *file_name)
{
	size_t size;
	const char *data;
	bool ret = -ENOENT;

	if (structure_name == NULL || file_name == NULL) {
		pnp_err("structure_name/file_name name is empty");
		goto exit;
	}

	data = pnp_file_read(file_name);
	if (data) {
		pnp_info("Structure %s loaded from file", structure_name);
		file->data = (char *) data;
		file->freeable = true;
		return 0;
	}
	pnp_info("File %s not available on disk", file_name);

	data = embed_file_get_content(structure_name, &size);
	if (data) {
		pnp_info("Structure %s loaded from embedded data", structure_name);
		file->data = (char *) data;
		file->freeable = false;
		return 0;
	}

exit:
	return ret;
}

void pnp_file_release(struct pnp_file *file)
{
	if (file->freeable)
		free(file->data);

	file->data = NULL;
	file->freeable = false;
}

/**
 * @brief Initialize PnP configuration
 *
 * Function initializes PnP configuration object
 *
 * @param conf PnP configuration object
 */
void pnp_configuration_init(struct pnp_configuration *conf)
{
	strncpy(conf->serial, "", PNP_SERIAL_SIZE);
	conf->serial[PNP_SERIAL_SIZE] = '\0';
	pnp_server_addresses_init(&conf->sa);
	conf->ping_send_period = 30;
	conf->pnp_socket_timeout = 70;
	conf->retry_wait = 1;
	conf->reconnect_wait = 10;
	conf->connect_timeout = 10;
	conf->ssl_negotiation_maxtime = 30;
	pnp_mapport_init(&conf->mp);
}

/**
 * @brief Deinitialize PnP configuration
 *
 * Function deinitializes (frees resources) of PnP configuration object
 *
 * @param conf PnP configuration object
 */
void pnp_configuration_deinit(struct pnp_configuration *conf)
{
	pnp_server_addresses_empty(&conf->sa);
}

