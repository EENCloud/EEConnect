/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_buffer.h"
#include <sys/uio.h>

/**
 * @brief Initialize buffer object (with buffer allocation)
 *
 * @param buf    Buffer object
 * @retval true  Successfully initialized buffer
 * @retval false Failed to initialize buffer
 */
bool pnp_buffer_init(struct pnp_buffer *buf)
{
	buf->maxsize = PNP_BUFFER_MAX_SIZE;
	buf->base = malloc(buf->maxsize);
	if (buf->base == NULL) {
		return false;
	}
	buf->start = 0;
	buf->size = 0;
	buf->block = false;
	return true;
}

/**
 * @brief Empty all data in buffer
 *
 * @param buf  Buffer object
 */
void pnp_buffer_empty(struct pnp_buffer *buf)
{
	buf->start = 0;
	buf->size = 0;
	buf->block = false;
}

/**
 * @brief Destroy buffer object (with deallocation)
 *
 * @param buf  Buffer object
 */
void pnp_buffer_destroy(struct pnp_buffer *buf)
{
	free(buf->base);
	buf->maxsize = 0;
	buf->start = 0;
	buf->size = 0;
	buf->block = false;
}

/**
 * @brief Read data to buffer, from specified socket
 *
 * @param buf        Buffer object
 * @param socket_fd  File descriptor of a socket
 * @retval true      Successfully received data (or no data at all)
 * @retval false     Error occurred when trying to read from socket
 */
bool pnp_buffer_read(struct pnp_buffer *buf, int socket_fd)
{
	struct iovec iov[2];
	int iovcnt;
	int ret;

	while (buf->size < buf->maxsize) {
		iov[0].iov_base = buf->base + (buf->start + buf->size) % buf->maxsize;
		iov[0].iov_len = (buf->base + buf->maxsize) - iov[0].iov_base;
		if ((size_t)(buf->maxsize - buf->size) <= iov[0].iov_len) {
			iov[0].iov_len = buf->maxsize - buf->size;
			iovcnt = 1;
		}
		else {
			iov[1].iov_base = buf->base;
			iov[1].iov_len = buf->maxsize - buf->size - iov[0].iov_len;
			iovcnt = 2;
		}
		ret = readv(socket_fd, iov, iovcnt);
		if (ret <= 0) {
			if (ret == 0) {
				/* EOF? */
				return false;
			}
			else if (errno == EINTR) {
				/* Interrupted */
				errno = 0;
				continue;
			}
			else if (errno == EAGAIN) {
				/* No more data is ready */
				errno = 0;
				break;
			}
			else {
				/* Error - we should close socket */
				return false;
			}
		}

		buf->block = false;
		buf->size += ret;
	}

	return true;
}

/**
 * @brief Write data from buffer, to specified socket
 *
 * @param buf        Buffer object
 * @param socket_fd  File descriptor of a socket
 * @retval true      Successfully sent data (or no data at all)
 * @retval false     Errors occurred when trying to send data to socket
 */
bool pnp_buffer_write(struct pnp_buffer *buf, int socket_fd)
{
	struct iovec iov[2];
	int iovcnt;
	int ret;

	while (buf->size > 0) {
		iov[0].iov_base = buf->base + buf->start;
		iov[0].iov_len = (buf->base + buf->maxsize) - iov[0].iov_base;
		if ((size_t)(buf->size) <= iov[0].iov_len) {
			iov[0].iov_len = buf->size;
			iovcnt = 1;
		}
		else {
			iov[1].iov_base = buf->base;
			iov[1].iov_len = buf->size - iov[0].iov_len;
			iovcnt = 2;
		}
		ret = writev(socket_fd, iov, iovcnt);
		if (ret <= 0) {
			if (ret == 0) {
				/* EOF */
				return false;
			}
			else if (errno == EINTR) {
				/* Interrupted */
				errno = 0;
				continue;
			}
			else if (errno == EAGAIN) {
				/* No more data is ready */
				errno = 0;
				break;
			}
			else {
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

/**
 * @brief Copy data from one buffer to another
 *
 * @param rbuf  Buffer object from which we copy data
 * @param wbuf  Buffer object to which we copy data
 * @param len   Length of data to be copied.
 * @pre Must be enough space in wbuf and enough data in rbuf before calling
 *      this function
 */
void pnp_buffer_copy(struct pnp_buffer *rbuf, struct pnp_buffer *wbuf, size_t len)
{
	int phases;
	size_t size1, size2 = 0, size3 = 0;
	void *rbase1, *rbase2 = NULL, *rbase3 = NULL;
	void *wbase1, *wbase2 = NULL, *wbase3 = NULL;
	size_t rbuf_size1;
	size_t rbuf_size2;
	size_t wbuf_size1;
	size_t wbuf_size2;

	/* Note: We assume there is enough space in wbuf and enough data in rbuf */

	/* We will use 1 or 2 areas of data of each buffer */
	rbuf_size1 = rbuf->maxsize - rbuf->start;
	if (rbuf_size1 > len)
		rbuf_size1 = len;
	rbuf_size2 = len - rbuf_size1;

	wbuf_size1 = wbuf->maxsize - (wbuf->start + wbuf->size) % wbuf->maxsize;
	if (wbuf_size1 > len)
		wbuf_size1 = len;
	wbuf_size2 = len - wbuf_size1;

	/* We divide copying data process into maximum 3 phases */
	if (rbuf_size2 > 0) {
		if (wbuf_size2 > 0) {
			if (rbuf_size1 == rbuf_size2) {
				/* 2 phases */
				phases = 2;
				size1 = rbuf_size1;
				size2 = rbuf_size2;

				rbase1 = rbuf->base + rbuf->start;
				rbase2 = rbuf->base;

				wbase1 = wbuf->base + (wbuf->start + wbuf->size) % wbuf->maxsize;
				wbase2 = wbuf->base;
			}
			else {
				/* 3 phases */
				phases = 3;
				if (rbuf_size1 < wbuf_size1) {
					size1 = rbuf_size1;
					size2 = wbuf_size1 - rbuf_size1;
					size3 = wbuf_size2;

					rbase1 = rbuf->base + rbuf->start;
					rbase2 = rbuf->base;
					rbase3 = rbuf->base + size2;

					wbase1 = wbuf->base + (wbuf->start + wbuf->size)
							% wbuf->maxsize;
					wbase2 = wbuf->base + (wbuf->start + wbuf->size + size1)
							% wbuf->maxsize;
					wbase3 = wbuf->base;
				}
				else {
					size1 = wbuf_size1;
					size2 = rbuf_size1 - wbuf_size1;
					size3 = rbuf_size2;

					rbase1 = rbuf->base + rbuf->start;
					rbase2 = rbuf->base + rbuf->start
							+ size1;
					rbase3 = rbuf->base;

					wbase1 = wbuf->base + (wbuf->start + wbuf->size)
							% wbuf->maxsize;
					wbase2 = wbuf->base;
					wbase3 = wbuf->base + size2;
				}
			}
		}
		else {
			/* 2 phases */
			phases = 2;
			size1 = rbuf_size1;
			size2 = rbuf_size2;

			rbase1 = rbuf->base + rbuf->start;
			rbase2 = rbuf->base;

			wbase1 = wbuf->base + (wbuf->start + wbuf->size) % wbuf->maxsize;
			wbase2 = wbase1 + size1;
		}
	}
	else {
		if (wbuf_size2 > 0) {
			/* 2 phases */
			phases = 2;
			size1 = wbuf_size1;
			size2 = wbuf_size2;

			rbase1 = rbuf->base + rbuf->start;
			rbase2 = rbase1 + size1;

			wbase1 = wbuf->base + (wbuf->start + wbuf->size) % wbuf->maxsize;
			wbase2 = wbuf->base;
		}
		else {
			/* 1 phase */
			phases = 1;
			size1 = len;

			rbase1 = rbuf->base + rbuf->start;

			wbase1 = wbuf->base + (wbuf->start + wbuf->size) % wbuf->maxsize;
		}
	}

	switch (phases) {
	case 1:
		memcpy(wbase1, rbase1, size1);
		break;
	case 2:
		memcpy(wbase1, rbase1, size1);
		memcpy(wbase2, rbase2, size2);
		break;
	case 3:
		memcpy(wbase1, rbase1, size1);
		memcpy(wbase2, rbase2, size2);
		memcpy(wbase3, rbase3, size3);
		break;
	}

	wbuf->size += len;
	rbuf->size -= len;
	rbuf->start = (rbuf->start + len) % rbuf->maxsize;
}
