/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_address.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/**
 * @brief Create new address object with specified address
 *
 * Function gets address in user-friendly hostname[:port] format, interprets
 * it, creates new address object and returns pointer to it.
 *
 * @param address IPv4 Address in hostname[:port] format. Default port is 80.
 * @retval Newly created address structure
 */
struct pnp_address* pnp_address_new_ipv4(const char *address)
{
	char *semicolon;
	int hostname_len;
	struct pnp_address *a;

	a = malloc(sizeof(struct pnp_address));
	if (a == NULL) {
		pnp_err("Cannot allocate pnp_address object");
		return NULL;
	}

	/* Get hostname and port from address */
	semicolon = strchr(address, ':');
	if (semicolon != NULL) {
		/* address form: hostname:port */
		hostname_len = (semicolon - address > PNP_HOSTNAME_MAXLEN - 1 ?
				PNP_HOSTNAME_MAXLEN - 1 : semicolon - address);

		strncpy(a->hostname, address, hostname_len);
		a->hostname[hostname_len] = '\0';

		strncpy(a->port, semicolon + 1, PNP_PORT_MAXLEN - 1);
		a->port[PNP_PORT_MAXLEN - 1] = '\0';
	}
	else {
		/* address form: hostname */
		strncpy(a->hostname, address, PNP_HOSTNAME_MAXLEN - 1);
		a->hostname[PNP_HOSTNAME_MAXLEN - 1] = '\0';

		strcpy(a->port, "80");
	}

	return a;
}

/**
 * @brief Create new address object with specified address
 *
 * Function gets address in user-friendly ip(string), port(number) format,
 * interprets it, creates new address object and returns pointer to it.
 *
 * @param ip    IP address of server
 * @param port  Port number of server
 * @return      Newly created address object or NULL on error
 */
struct pnp_address* pnp_address_new_ip_port(const char* ip, int port)
{
	struct pnp_address *a;
	int hostname_len = strlen(ip);

	if (hostname_len > PNP_HOSTNAME_MAXLEN - 1) {
		pnp_err("The received IP / hostname does not fit into %d characters string",
			PNP_HOSTNAME_MAXLEN - 1);
		return NULL;
	}

	a = malloc(sizeof(struct pnp_address));
	if (a == NULL) {
		pnp_err("Cannot allocate pnp_address object");
		return NULL;
	}

	strncpy(a->hostname, ip, PNP_HOSTNAME_MAXLEN - 1);
	a->hostname[hostname_len] = '\0';

	snprintf(a->port, PNP_PORT_MAXLEN - 1, "%d", port);
	a->port[PNP_PORT_MAXLEN - 1] = '\0';

	return a;
}

/**
 * @brief Create new address object with specified hostname and port
 *
 * @param hostname  Hostname for new address object
 * @param port      Port for new address object
 * @return          Newly created address object
 */
struct pnp_address* pnp_address_new_hostname_port(const char *hostname,
		const char *port)
{
	struct pnp_address *a;
	a = malloc(sizeof(struct pnp_address));
	if (a == NULL) {
		pnp_err("Cannot allocate pnp_address object");
		return NULL;
	}

	strncpy(a->hostname, hostname, PNP_HOSTNAME_MAXLEN);
	a->hostname[PNP_HOSTNAME_MAXLEN] = '\0';
	strncpy(a->port, port, PNP_PORT_MAXLEN);
	a->port[PNP_PORT_MAXLEN] = '\0';

	return a;
}

/**
 * @brief Release memory for address structure
 *
 * Release allocated memory for specified address structure.
 *
 * @param a Address structure
 */
void pnp_address_release(struct pnp_address *a)
{
	if (a) {
		free(a);
	}
}
