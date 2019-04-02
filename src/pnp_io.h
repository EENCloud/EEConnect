/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_IO_H_
#define SRC_PNP_IO_H_

#include <openssl/ssl.h>
#include <stdbool.h>

struct pnp_connection;

struct pnp_io {
	int (*accept)(struct pnp_connection *c);
	int (*connect)(struct pnp_connection *c);
	int (*write_buffer)(struct pnp_connection *c, void *buffer, int len,
			int flags);
	bool (*read)(struct pnp_connection *c);
	bool (*write)(struct pnp_connection *c);
	void (*close)(struct pnp_connection *c);
};

typedef int (*pnp_io_setup_t)(struct pnp_connection *c, void *ctx);

void pnp_io_ssl_info_callback(const SSL *s, int where, int ret);
int pnp_io_ssl_load_cert(const char *structure_name, const char *file_name,
		SSL_CTX *ctx);
int pnp_io_ssl_load_key(const char *structure_name, const char *file_name,
		SSL_CTX *ctx);
int pnp_io_ssl_load_ca(const char *structure_name, const char *file_name,
		SSL_CTX *ctx);
int pnp_connection_setup_io_plain(struct pnp_connection *c, void *ctx);
int pnp_connection_setup_io_ssl(struct pnp_connection *c, void *ctx);

#endif /* SRC_PNP_IO_H_ */
