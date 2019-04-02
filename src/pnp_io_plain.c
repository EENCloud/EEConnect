/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_connection.h"
#include "pnp_io.h"

#include <sys/socket.h>
#include <sys/uio.h>

static int pnp_io_plain_write_buffer(struct pnp_connection *c, void *buffer,
				int len, int flags)
{
	int ret;

retry:
	ret = send(c->socket_fd, buffer, len, flags | MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret == 0) {
			/* EOF */
			pnp_err("EOF");
		} else if (errno == EINTR) {
			/* Interrupted by signal - continue */
			errno = 0;
			goto retry;
		} else {
			/* Error */
			pnp_err("Error while writing to socket");
		}

                pnp_connection_set_state(c, PNP_DISCONNECTED);

		return -EIO;
	}

	return ret;
}

static bool pnp_io_plain_read(struct pnp_connection *c)
{
	struct pnp_buffer *buf = &c->rbuf;
	int ret = 0;

	while (buf->size < buf->maxsize) {
		struct iovec iov[2];
		int iovcnt;

		iov[0].iov_base = buf->base + (buf->start + buf->size) % buf->maxsize;
		iov[0].iov_len = (buf->base + buf->maxsize) - iov[0].iov_base;

		if ((size_t)(buf->maxsize - buf->size) <= iov[0].iov_len) {
			iov[0].iov_len = buf->maxsize - buf->size;
			iovcnt = 1;
			iov[1].iov_base = 0;
			iov[1].iov_len = 0;
		} else {
			iov[1].iov_base = buf->base;
			iov[1].iov_len = buf->maxsize - buf->size - iov[0].iov_len;
			iovcnt = 2;
		}

		ret = readv(c->socket_fd, iov, iovcnt);
		if (ret <= 0) {
			if (ret == 0) {
				/* EOF? */
				return false;
			} else if (errno == EINTR) {
				/* Interrupted */
				errno = 0;
				continue;
			} else if (errno == EAGAIN) {
				/* No more data is ready */
				errno = 0;
				break;
			} else {
				/* Error - we should close socket */
				return false;
			}
		}

		buf->block = false;
		buf->size += ret;
	}

	return true;
}

static bool pnp_io_plain_write(struct pnp_connection *c)
{
	struct pnp_buffer *buf = &c->wbuf;
	int ret;

	while (buf->size > 0) {
		struct iovec iov[2];
		int iovcnt;

		iov[0].iov_base = buf->base + buf->start;
		iov[0].iov_len = (buf->base + buf->maxsize) - iov[0].iov_base;

		if ((size_t)(buf->size) <= iov[0].iov_len) {
			iov[0].iov_len = buf->size;
			iovcnt = 1;
			iov[1].iov_base = 0;
			iov[1].iov_len = 0;
		} else {
			iov[1].iov_base = buf->base;
			iov[1].iov_len = buf->size - iov[0].iov_len;
			iovcnt = 2;
		}

		ret = writev(c->socket_fd, iov, iovcnt);
		if (ret <= 0) {
			if (ret == 0) {
				/* EOF */
				return false;
			} else if (errno == EINTR) {
				/* Interrupted */
				errno = 0;
				continue;
			} else if (errno == EAGAIN) {
				/* No more data is ready */
				errno = 0;
				break;
			} else {
				/* Error - we should close socket */
				pnp_err("Socket error");
				return false;
			}
		}

		buf->block = false;
		buf->start = (buf->start + ret) % buf->maxsize;
		buf->size -= ret;
	}

	return true;
}

static struct pnp_io plain_io = {
	.write_buffer = pnp_io_plain_write_buffer,
	.read = pnp_io_plain_read,
	.write = pnp_io_plain_write,
};

int pnp_connection_setup_io_plain(struct pnp_connection *c, void *ctx)
{
	pnp_connection_setup_io(c, &plain_io, NULL);

	return 0;
}
