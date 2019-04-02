/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_BUFFER_H_
#define SRC_PNP_BUFFER_H_

#include "pnp_common.h"

//#define PNP_BUFFER_MAX_SIZE (1024*1024)
#define PNP_BUFFER_MAX_SIZE (1024*128)

struct pnp_buffer {
	void *base;
	size_t start;
	size_t size;
	size_t maxsize;

	bool block;
};

bool pnp_buffer_init(struct pnp_buffer *buf);
void pnp_buffer_empty(struct pnp_buffer *buf);
void pnp_buffer_destroy(struct pnp_buffer *buf);
bool pnp_buffer_read(struct pnp_buffer *buf, int socket_fd);
bool pnp_buffer_write(struct pnp_buffer *buf, int socket_fd);

void pnp_buffer_copy(struct pnp_buffer *rbuf, struct pnp_buffer *wbuf, size_t len);

#endif /* SRC_PNP_BUFFER_H_ */
