/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_server_addresses.h"

/**
 * @brief Add address from pnp_address object
 *
 * @param sa Server addresses structure
 * @param a Address structure that we want to add
 * @retval true Address was added
 * @retval false Address was not added
 */
bool pnp_server_addresses_add(struct pnp_server_addresses *sa, struct pnp_address *a)
{
	void *retval = realloc(sa->address, (sa->num + 1) * sizeof(struct pnp_address*));
	if (retval == NULL) {
		pnp_err("Cannot realocate pnp_address table");
		return false;
	}
	else {
		sa->address = (struct pnp_address**)retval;
	}
	sa->address[sa->num++] = a;
	return true;
}

/**
 * @brief Add address from hostname[:port] string
 *
 * @param sa Server addresses structure
 * @param address Null terminated array of characters in form hostname[:port].
 *                Default port is 80.
 * @retval true Address was added
 * @retval false Address was not added
 */
bool pnp_server_addresses_add_ipv4_from_string(struct pnp_server_addresses *sa,
		const char* address)
{
	struct pnp_address *a;

	a = pnp_address_new_ipv4(address);
	if (a == NULL) {
		return false;
	}

	return pnp_server_addresses_add(sa, a);
}

bool pnp_server_addresses_add_ip_port(struct pnp_server_addresses *sa,
		const char *ip, int port)
{
	struct pnp_address *a;

	a = pnp_address_new_ip_port(ip, port);
	if (a == NULL) {
		return false;
	}

	return pnp_server_addresses_add(sa, a);
}

/**
 * @brief Initialize server addresses object
 *
 * Function initialized server addresses object
 *
 * @param sa Pointer to server addresses object
 */
void pnp_server_addresses_init(struct pnp_server_addresses *sa)
{
	sa->address = NULL;
	sa->num = 0;
}

/**
 * @brief Create new server addresses object
 *
 * Function creates new (empty) server addresses object
 *
 * @return Pointer to new object or NULL if not successful
 */
struct pnp_server_addresses* pnp_server_addresses_new(void)
{
	struct pnp_server_addresses *sa =
			malloc(sizeof(struct pnp_server_addresses));

	pnp_server_addresses_init(sa);

	return sa;
}

/**
 * @brief Release all resources for object
 *
 * Function releases all resource for server addresses object. This includes
 * releasing memory for single addresses, addresses table and object itself.
 *
 * @param sa Server addresses object
 */
void pnp_server_addresses_release(struct pnp_server_addresses *sa)
{
	/* Remove all address objects */
	pnp_server_addresses_empty(sa);

	/* Release main object */
	free(sa);
}

/**
 * @brief Reomve all addresses from object
 *
 * Function releases all addresses that belong to object and goes back to
 * after init state.
 *
 * @param sa PnP server addresses object
 */
void pnp_server_addresses_empty(struct pnp_server_addresses *sa)
{
	int i;

	/* Release all single addresses */
	for (i = 0; i < sa->num; i++)
		pnp_address_release(sa->address[i]);

	/* Empty main object */
	free(sa->address);
	sa->address = NULL;
	sa->num = 0;
}
