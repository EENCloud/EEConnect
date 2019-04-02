/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include "pnp_channel.h"
#include "pnp_thread_helper.h"
#include "pnp_connection_typedef.h"
#include "pnp_cmd_type.h"
#include "pnp_cmd.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <fcntl.h>

#include <pthread.h>

/* Static functions -------------------------------------------------------- */

/**
 * @brief Initialize channel object
 *
 * Function initializes channel object to default values.
 *
 * @param ch PnP channel object
 */
static bool pnp_channel_init_with_id(struct pnp_channel *ch, int channel_id,
				struct pnp_connection *c)
{
	ch->channel_id = channel_id;
	ch->socket_fd = -1;

	/* Initialize buffer */
	if (!pnp_buffer_init(&ch->rbuf)) {
		pnp_err("Failed to initialize buffer for channel");
		return false;
	}
	/* Initialize buffer */
	if (!pnp_buffer_init(&ch->wbuf)) {
		pnp_err("Failed to initialize buffer for channel");
		pnp_buffer_destroy(&ch->rbuf);
		return false;
	}

	ch->c = c;
	ch->shutdown = false;
	ch->closed_int = false;
	ch->closed_ext = false;
#ifdef PNP_DEBUG
	ch->debug_data_out_id = 0;
	ch->debug_data_in_id = 0;
#endif

	return true;
}

/* Global functions -------------------------------------------------------- */

/**
 * @brief Create new object, initialize and return
 *
 * Allocate and initialize new PnP channel object and return pointer to it.
 *
 * @return Pointer to newly created PnP channel object
 */
struct pnp_channel* pnp_channel_new(struct pnp_connection *c)
{
	struct pnp_channel *ch = malloc(sizeof(struct pnp_channel));

	if (ch == NULL) {
		pnp_err("Cannot allocate pnp_channel object");
		return NULL;
	}

	if (!pnp_channel_init_with_id(ch, -1, c)) {
		free(ch);
		return NULL;
	}
	return ch;
}

/**
 * @brief Create new object with specified channel id, initialize and return
 *
 * Allocate and initialize new PnP channel object with specified id
 * and return pointer to it.
 *
 * @return Pointer to newly created PnP channel object
 */
struct pnp_channel* pnp_channel_new_with_id(struct pnp_connection *c,
					int channel_id)
{
	struct pnp_channel *ch = malloc(sizeof(struct pnp_channel));

	if (ch == NULL) {
		pnp_err("Cannot allocate pnp_channel object");
		return NULL;
	}

	if (!pnp_channel_init_with_id(ch, channel_id, c)) {
		free(ch);
		return NULL;
	}
	return ch;
}

/**
 * @brief Close current channel (if active)
 *
 * Function closes current channel (if active) and sets file descriptor
 * to -1.
 *
 * @param ch PnP channel object
 */
void pnp_channel_close(struct pnp_channel *ch)
{
	/* Close connection */
	if (ch->socket_fd != -1)
		close(ch->socket_fd);

	/* Empty buffers */
	pnp_buffer_empty(&ch->rbuf);
	pnp_buffer_empty(&ch->wbuf);

	/* Clear channel and socket info */
	ch->channel_id = -1;
	ch->socket_fd = -1;

	ch->shutdown = false;
	ch->closed_ext = false;
	ch->closed_int = false;

#ifdef PNP_DEBUG
	ch->debug_data_out_id = 0;
	ch->debug_data_in_id = 0;
#endif
}

/**
 * @brief Release all resources for channel
 *
 * Function closes the channel (if not already closed) and releases
 * allocated memory.
 *
 * @pre ch is an existing object and no
 * @pre No other thread will use this channel
 * @param ch PnP channel object
 */
void pnp_channel_release(struct pnp_channel *ch)
{
	pnp_channel_close(ch);
	pnp_buffer_destroy(&ch->rbuf);
	pnp_buffer_destroy(&ch->wbuf);

	free(ch);
}

/**
 * @brief Connect channel to specified address
 *
 * Create new socket and connect to specified address
 *
 * @param ch          PnP channel object
 * @param ip          IP address that we will connect to
 * @param i_port      Port number to which we will connect to
 * @retval true   Channel successfully connected
 * @retval false  Failed to connect channel to end point
 */
bool pnp_channel_connect_to(struct pnp_channel *ch, char *ip, int i_port)
{
	char s_port[6 + 1];
	struct addrinfo *addr_result, *addr_p;
	struct addrinfo hints;
	int ret;
	int fcntl_flags = 0;

	/* Convert port to string */
	snprintf(s_port, 6, "%d", (int)i_port);
	s_port[6] = '\0';

	/* Set hints */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = 0;

	/* Get address list for hostname */
	ret = getaddrinfo(ip, s_port, &hints, &addr_result);
	if (ret != 0) {
		pnp_err("getaddrinfo: %s", gai_strerror(ret));
		return false;
	}

	/* Try to connect to some address from address list */
	for (addr_p = addr_result; addr_p != NULL; addr_p = addr_p->ai_next) {
		ch->socket_fd = socket(addr_p->ai_family, addr_p->ai_socktype,
				addr_p->ai_protocol);

		/* Check if socket socket creation was successful */
		if (ch->socket_fd == -1) {
			pnp_warn("Socket == -1. Trying another address.");
			continue;
		}

		// TODO this should be non-blocking call
		/* Try to connect to address */
		if (connect(ch->socket_fd, addr_p->ai_addr, addr_p->ai_addrlen) != -1) {
			/* We are successfully connected */
			pnp_info("Successfully connected! channelId:%d ip:%s port:%d",
				 ch->channel_id, ip, i_port);
			break;
		}

		/* Connection was not successful so close socket and try another
		 * address */
		close(ch->socket_fd);
		ch->socket_fd = -1;
	}

	/* Free addrinfo resources */
	freeaddrinfo(addr_result);

	/* Check if we are connected successfully */
	if (ch->socket_fd == -1) {
		pnp_warn("Connection to address '%s:%s' failed", ip, s_port);
		pnp_channel_release(ch);
		return false;
	}

	/* Set nonblocking operations */
	fcntl_flags = fcntl(ch->socket_fd, F_GETFL, 0);
	fcntl_flags |= O_NONBLOCK;
	fcntl(ch->socket_fd, F_SETFL, fcntl_flags);

	/* We are successfully connected */
	return true;
}

/**
 * @brief Initialize channel container
 *
 * Function initialized channel container to default values (empty container).
 *
 * @param ch_con PnP channel object
 */
bool pnp_channel_container_init(struct pnp_channel_container *ch_con)
{
	memset(ch_con, 0x0, sizeof(struct pnp_channel_container));
	ch_con->channel_idx = 0;
	return true;
}

/**
 * @brief Create and initialize new channel container object
 *
 * Function creates new channel container object and initializes it.
 *
 * @return Pointer to object or NULL if creating object failed
 */
struct pnp_channel_container* pnp_channel_container_new(void)
{
	struct pnp_channel_container *ch_con = malloc(sizeof(struct pnp_channel_container));

	if (ch_con == NULL) {
		pnp_err("Cannot allocate pnp_channel_container object");
		return NULL;
	}

	if (!pnp_channel_container_init(ch_con)) {
		free(ch_con);
		return NULL;
	}
	return ch_con;
}

/**
 * @brief Empty channel container
 *
 * @param ch_con  PnP channel container object
 */
void pnp_channel_container_empty(struct pnp_channel_container *ch_con)
{
	int i;

#if PNP_DEBUG
	if (ch_con == NULL) {
		pnp_err("Channel container is already released");
		return;
	}
#endif

	/* Release all channels */
	for (i = 0; i < PNP_CHANNEL_CONTAINER_TABLE_SIZE; i++) {
		if (ch_con->table[i] != NULL) {
			pnp_channel_release(ch_con->table[i]);
			ch_con->table[i] = NULL;
		}
	}

	ch_con->channel_idx = 0;
}

/**
 * @brief Destroy channel container object
 *
 * @param ch_con  PnP channel container object
 * @return
 */
void pnp_channel_container_destroy(struct pnp_channel_container *ch_con)
{
	pnp_channel_container_empty(ch_con);
}

/**
 * @brief Releases all resources referred to channel container
 *
 * Function releases all channels in container and container itself
 *
 * @pre ch_con is an existing object
 * @param ch_con PnP channel container object
 */
void pnp_channel_container_release(struct pnp_channel_container *ch_con)
{
	if (ch_con == NULL) {
		pnp_err("Channel container is already released");
		return;
	}

	pnp_channel_container_destroy(ch_con);

	/* Dealocate memory for container object */
	free(ch_con);
}

/**
 * @brief Open and add new channel to the container
 *
 * Function creates new channel, opens new socket to specified ip:i_port and
 * saves information to channel container
 *
 * @param ch_con        PnP channel container object
 * @param c             PnP connection object
 * @param channel_id    Pointer to channel ID for this connection. If value is
 *                      -1, than first free port is used and value is
 *                      overwritten
 * @param ip            IP address that we will connect to
 * @param i_port_socket If ip!=NULL: port number to which we will connect to,
 *                      else: socket_fd for this channel
 * @retval true   Successfully created channel and opened connection to it
 * @retval false  Failed to create channel or connect to it
 */
bool pnp_channel_container_add(struct pnp_channel_container *ch_con,
			struct pnp_connection *c,
			int *channel_id, char *ip, int i_port_socket)
{
	struct pnp_channel *ch;

	/* If channel_id == -1 than we should generate next free channel id */
	if (*channel_id == -1) {
		for (*channel_id = 0; *channel_id < PNP_CHANNEL_CONTAINER_TABLE_SIZE; (*channel_id)++) {
			if (ch_con->table[*channel_id] == NULL)
				break;
		}
		if (*channel_id >= PNP_CHANNEL_CONTAINER_TABLE_SIZE) {
			return false;
		}
	}

	/* First check if requested channelId is not reserved already */
	if (ch_con->table[*channel_id] != NULL) {
		pnp_err("Channel id is already used. Failed to open channel %d.", *channel_id);
		return false;
	}

	/* Create new channel object */
	if ((ch = pnp_channel_new_with_id(c, *channel_id)) == NULL) {
		return false;
	}

	/* Try to connect to ip:i_port_socket, but only if ip!=NULL */
	if (ip != NULL) {
		if (!pnp_channel_connect_to(ch, ip, i_port_socket)) {
			pnp_err("Failed to connect to channel %s:%d", ip, i_port_socket);
			errno = 0;
			pnp_msg_send_closechannel(c, *channel_id);
			return false;
		}
	}
	else {
		/* We are already connected - just save socket_fd */
		ch->socket_fd = i_port_socket;
	}

	/* Save information about opened channel */
	ch_con->table[*channel_id] = ch;

	/* We are successfully connected */
	return true;
}

/**
 * @brief Close channel and remove it from container
 *
 * Function closes connection within specified channel and removes it from
 * container
 *
 * @param ch_con      PnP channel container object
 * @param channel_id  Channel id that should be closed
 * @retval true   Successfully closed connection and removed from container
 * @retval false  Failed to close connection (probably there is no such
 *                connection)
 */
bool pnp_channel_container_remove(struct pnp_channel_container *ch_con,
		int channel_id)
{
	pnp_info("Remove channelId:%d from container", channel_id);

	/* Check if there is such a channel in a container */
	if (ch_con->table[channel_id] == NULL) {
		pnp_warn("Connection with channelId:%d doesn't exist", channel_id);
		return false;
	}

	/* Free and remove channel object from container */
	pnp_channel_release(ch_con->table[channel_id]);
	ch_con->table[channel_id] = NULL;

	return true;
}

/**
 * @brief Set fd_set structure for use on select() call
 *
 * @param ch_con PnP channel container object
 * @param r_fds  Pointer to fd_set for read descriptors
 * @param w_fds  Pointer to fd_set for write descriptors
 * @param maxfd  Pointer to maximum file descriptor, which may be changed
 *               by this function
 */
void pnp_channel_container_set_fds(struct pnp_channel_container *ch_con,
		fd_set *r_fds, fd_set *w_fds, int *maxfd)
{
	int ch_id;
	for (ch_id = 0; ch_id < PNP_CHANNEL_CONTAINER_TABLE_SIZE; ch_id++) {
		if (ch_con->table[ch_id]) {
			pnp_channel_set_fds(ch_con->table[ch_id], r_fds, w_fds, maxfd);
		}
	}
}

#define PNP_DATA_MAX_SIZE (32767)
#define PNP_DATA_RESERVED_FOR_CMDS (4096)

bool pnp_channel_send_data(struct pnp_channel *ch)
{
	struct pnp_connection *c = ch->c;
	struct pnp_buffer *wbuf = &c->wbuf;
	struct pnp_buffer *rbuf = &ch->rbuf;
	uint8_t *wbase = wbuf->base;
	size_t place;
	ssize_t splace;
	uint16_t len16;

	while (1) {
		splace = wbuf->maxsize - wbuf->size - PNP_DATA_RESERVED_FOR_CMDS;

		/* Check if there is enough place for header + data */
		if (splace < 5 || rbuf->size < 1) {
			/* Prevent writing to this buffer until there is some more space */
			//    wbuf->block = true;
			return false;
		}
		place = splace;

		/* Calculate size which can be transferred and fill headers */
		place -= 4;
		if (place > PNP_DATA_MAX_SIZE)
			place = PNP_DATA_MAX_SIZE;
		len16 = (place >= rbuf->size) ? rbuf->size : place;
		wbase[(wbuf->start + wbuf->size + 0) % wbuf->maxsize] = PNP_CMD_DATA;
		wbase[(wbuf->start + wbuf->size + 1) % wbuf->maxsize] = (uint8_t)ch->channel_id;
		wbase[(wbuf->start + wbuf->size + 2) % wbuf->maxsize] = len16 >> 8;
		wbase[(wbuf->start + wbuf->size + 3) % wbuf->maxsize] = len16 & 0xFF;
		wbuf->size += 4;

		/* Copy buffers */
		pnp_buffer_copy(rbuf, wbuf, len16);

#ifdef PNP_DEBUG
		pnp_info("[%d:%d] Send %d DATA bytes", ch->channel_id, ch->debug_data_out_id++, (int) len16);
#endif
	}

	return true;
}

/**
 * @brief Set fd_set and maxfd for PnP channel for use in select() call
 *
 * @param ch     PnP channel object
 * @param r_fds  Pointer to fd_set for read descriptors
 * @param w_fds  Pointer to fd_set for write descriptors
 * @param maxfd  Pointer to maximum file descriptor, which may be changed
 *               by this function
 */
void pnp_channel_set_fds(struct pnp_channel *ch, fd_set *r_fds, fd_set *w_fds, int *maxfd)
{
	if (ch->wbuf.size > 0 && !ch->closed_int) {
		FD_SET(ch->socket_fd, w_fds);
		if (ch->socket_fd > *maxfd)
			*maxfd = ch->socket_fd;
	}
	if (ch->rbuf.size < ch->rbuf.maxsize && !ch->closed_int && !ch->closed_ext) {
		FD_SET(ch->socket_fd, r_fds);
		if (ch->socket_fd > *maxfd)
			*maxfd = ch->socket_fd;
	}
}

/**
 * @brief Perform single step of read and write operations for a PnP channel
 *
 * Function performs single step of read and write operation for PnP channel,
 * as well as closes inactive channels (closed by PnP cmd or by socket).
 *
 * @param ch     PnP channel object
 * @param r_fds  Pointer to fd_set for read descriptors
 * @param w_fds  Pointer to fd_set for write descriptors
 */
void pnp_channel_step(struct pnp_channel *ch, fd_set *r_fds, fd_set *w_fds)
{
	struct pnp_connection *c = ch->c;

	/* Send and receive data */
	pnp_channel_write_step(ch, w_fds);
	pnp_channel_read_step(ch, r_fds);

	/* Check if channel is pending for closing */
	if (
	(ch->closed_ext && ch->closed_int) ||
			(ch->closed_ext && ch->wbuf.size <= 0) ||
			(ch->closed_int && ch->rbuf.size <= 0)
			) {
		/* Check if there is enough place for header + data */
		if (ch->closed_ext || pnp_msg_send_closechannel(c, ch->channel_id)) {
			pnp_channel_container_remove(&c->ch_con, ch->channel_id);
		}
	}
}

/**
 * @brief Read data from socket to channel buffer and than to connection
 *        buffer (if there is enough space)
 *
 * @param ch     PnP channel object
 * @param r_fds  Pointer to fd_set structure returned from select() call
 * @retval true  No errors occurred when reading from channel socket
 * @retval false Errors occurred when reading from channel socket
 */
bool pnp_channel_read_step(struct pnp_channel *ch, fd_set *r_fds)
{
	bool success = true;
	if (FD_ISSET(ch->socket_fd, r_fds)) {
		/* Read data */
		if (!pnp_buffer_read(&ch->rbuf, ch->socket_fd)) {
			pnp_err("Failed to read from channel end point. "
					"Setting closed_int for channel %d\n",
					ch->channel_id);
			ch->closed_int = true;
			success = false;
		}
	}

	/* Copy data to connection buffer */
	if (!(ch->closed_ext)) {
		pnp_channel_send_data(ch);
	}

	return success;
}

/**
 * @brief Write data from channel buffer to socket
 *
 * @param ch     PnP channel object
 * @param w_fds  Pointer to fd_set structure returned from select() call
 * @retval true  No errors when writing data to channel socket
 * @retval false Errors occurred when writing to channel socket
 * @post Function modifies process_cmds_continue variable of pnp_connection
 *       object, in order to further process pending data to channel buffer
 */
bool pnp_channel_write_step(struct pnp_channel *ch, fd_set *w_fds)
{
	struct pnp_connection *c = ch->c;

	if (FD_ISSET(ch->socket_fd, w_fds)) {
		if (ch->wbuf.block)
			c->process_cmds_continue = true;
		/* Write data */
		if (!pnp_buffer_write(&ch->wbuf, ch->socket_fd)) {
			pnp_err("Failed to write to channel end point. "
					"Setting closed_int for channel %d\n",
					ch->channel_id);
			ch->closed_int = true;
			return false;
		}
	}

	return true;
}
