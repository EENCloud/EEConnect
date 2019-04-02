/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include "pnp_cmd.h"
#include "pnp_connection.h"
#include "pnp_io.h"
#include "pnp_thread_helper.h"

#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include <signal.h>

/* Static functions -------------------------------------------------------- */

static void dummy_handler(int num)
{
	(void)(num);
}

/**
 * @brief Update timeout values for a PnP connection, from specified timestamp
 *
 * @param c   PnP connection object
 * @param cur Pointer to timespec structure specifying current time
 */
static void pnp_connection_update_timeout(struct pnp_connection *c,
		struct timespec *cur)
{
	struct timespec *ts = &c->pselect_ts;

	ts->tv_nsec = 0;
	ts->tv_sec = (c->last_ping + c->conf->ping_send_period + 1) - cur->tv_sec;
	if ((c->last_in + c->conf->pnp_socket_timeout + 1) - cur->tv_sec < ts->tv_sec)
		ts->tv_sec = (c->last_in + c->conf->pnp_socket_timeout + 1) - cur->tv_sec;
	if ((c->last_out + c->conf->pnp_socket_timeout + 1) - cur->tv_sec < ts->tv_sec)
		ts->tv_sec = (c->last_out + c->conf->pnp_socket_timeout + 1) - cur->tv_sec;
	if (ts->tv_sec < 0)
		ts->tv_sec = 0;
}

/* Global functions -------------------------------------------------------- */
/**
 * @brief Initialize PnP connection object
 *
 * Function initializes connection object to default values.
 *
 * @param c      PnP connection object
 * @retval true  Successfully initialized
 * @retval false Failed to initialize
 */
bool pnp_connection_init(struct pnp_connection *c,
	struct pnp_configuration *conf)
{
	c->socket_fd = -1;
	c->redirect_address = NULL;

	c->connection_state = PNP_INITIALIZED;
	c->io = NULL;

	c->cmd_continue = false;
	c->process_cmds_continue = false;
	c->dbus = NULL;

	c->conf = conf;

	return true;
}

/**
 * @brief Create new PnP object, initialize and return
 *
 * Allocate and initialize new PnP connection structure and return pointer
 * to it.
 *
 * @return Pointer to newly created PnP connection object or
 *         NULL if creation or initialization failed
 */
struct pnp_connection* pnp_connection_new(void)
{
	struct pnp_connection *c = malloc(sizeof(*c));

	if (!c) {
		pnp_err("Cannot allocate pnp_connection object");
		return NULL;
	}

	memset(c, 0x0, sizeof(struct pnp_connection));

	if (!pnp_channel_container_init(&c->ch_con))
		goto free_connection;

	if (!pnp_connection_proxy_init(&c->proxy, c))
		goto destroy_channel_container;

	if (!pnp_buffer_init(&c->rbuf))
		goto release_connection_proxy;

	if (!pnp_buffer_init(&c->wbuf))
		goto destroy_rbuf;

	return c;

destroy_rbuf:
	pnp_buffer_destroy(&c->rbuf);
release_connection_proxy:
	pnp_connection_proxy_release(&c->proxy);
destroy_channel_container:
	pnp_channel_container_destroy(&c->ch_con);
free_connection:
	free(c);

	return NULL;
}

/**
 * @brief Close current PnP connection and all it's objects
 *
 * Function closes current PnP connection and all it's objects
 *
 * @pre      redirect_address should be explicitly freed
 * @param c  PnP connection object
 */
void pnp_connection_close(struct pnp_connection *c)
{
	pnp_info("Close PNP Connection");

	if (c->io && c->io->close)
		c->io->close(c);

	if (c->socket_fd != -1)
		close(c->socket_fd);
	c->socket_fd = -1;

	c->process_cmds_continue = false;
	c->cmd_continue = false;

	pnp_connection_proxy_close(&c->proxy);
	pnp_channel_container_empty(&c->ch_con);

	pnp_buffer_empty(&c->rbuf);
	pnp_buffer_empty(&c->wbuf);
}

/**
 * @brief Release all resources for connection
 *
 * Function closes the connection (if not already closed) and releases
 * allocated memory.
 *
 * @param c  PnP connection object
 */
void pnp_connection_release(struct pnp_connection *c)
{
	pnp_connection_close(c);

	pnp_connection_proxy_release(&c->proxy);
	pnp_address_release(c->redirect_address);
	pnp_channel_container_destroy(&c->ch_con);

	pnp_buffer_destroy(&c->rbuf);
	pnp_buffer_destroy(&c->wbuf);

	free(c);
}

int pnp_connection_wait_for_data(struct pnp_connection *c,
				struct timespec *timestamp,
				bool write)
{
	struct timespec timeout;
	fd_set fds;
	int ret;

retry:
	FD_ZERO(&fds);
	FD_SET(c->socket_fd, &fds);

	clock_gettime(CLOCK_MONOTONIC, &timeout);
	timeout.tv_sec = timestamp->tv_sec - timeout.tv_sec;
	timeout.tv_nsec = timestamp->tv_nsec - timeout.tv_nsec;

	if (timeout.tv_nsec < 0) {
		timeout.tv_nsec += 1000000000;
		timeout.tv_sec -= 1;
	}

	if (write)
		ret = pselect(c->socket_fd + 1, NULL, &fds, NULL, &timeout, NULL);
	else
		ret = pselect(c->socket_fd + 1, &fds, NULL, NULL, &timeout, NULL);

	if (ret < 0 && errno == EINTR)
		goto retry;

	return ret;
}

static bool wait_for_connection(struct pnp_connection *c)
{
	struct timespec stop_ts;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &stop_ts);
	stop_ts.tv_sec += c->conf->connect_timeout;

	ret = pnp_connection_wait_for_data(c, &stop_ts, true);

	if (ret <= 0) {
		if (ret < 0)
			pnp_warn("Error on connect()");
		else
			pnp_warn("Timeout on connect()");

		return false;
	}

	return true;
}

int pnp_connection_accept(struct pnp_connection **c,
			int listen_fd, int af,
			struct pnp_configuration *conf,
			pnp_io_setup_t setup_io, void *io_data)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	struct pnp_connection *c_tmp;
	int fd;
	int fcntl_flags;
	char str[INET6_ADDRSTRLEN];
	struct timeval tv = {
		.tv_sec = 70,
		.tv_usec = 0,
	};
	int err;
	int ret;

	fd = accept(listen_fd, (struct sockaddr *) &addr, &addr_len);
	if (fd < 0) {
		err = -errno;
		errno = 0;

		if (err != -EINTR)
			pnp_err("Error on accepting connection");

		return err;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		err = -errno;
		errno = 0;
		return err;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		err = -errno;
		errno = 0;
		return err;
	}

	inet_ntop(AF_INET, (const void *) &addr.sin_addr, str,
		INET6_ADDRSTRLEN);

	pnp_info("Accepted connection from %s:%d", str,
		(int) ntohs(addr.sin_port));

	c_tmp = pnp_connection_new();
	if (!c) {
		pnp_err("Failed to create connection");
		return -ENOMEM;
	}

	if (!pnp_connection_init(c_tmp, conf)) {
		pnp_err("Failed to initialize connection");
		err = -EINVAL;
		goto connection_release;
	}

	err = setup_io(c_tmp, io_data);
	if (err)
		goto connection_release;

	c_tmp->server_mode = true;
	c_tmp->socket_fd = fd;

	if (c_tmp->io->accept) {
		err = c_tmp->io->accept(c_tmp);
		if (err)
			goto connection_release;
	}

	/* Set non-blocking operations */
	fcntl_flags = fcntl(fd, F_GETFL, 0);
	fcntl_flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, fcntl_flags);

	*c = c_tmp;

	return 0;

connection_release:
	pnp_connection_release(c_tmp);
	return err;
}

/**
 * @brief Connect to specified server
 *
 * Function tries to connect to address specified as argument.
 *
 * @param c       PnP Connection structure
 * @param a       Address information
 * @retval true   Successfully connected to server
 * @retval false  Connection to server failed
 */
bool pnp_connection_connect(struct pnp_connection *c, struct pnp_address *a)
{
	struct addrinfo *addr_result, *addr_p;
	struct addrinfo hints;
	int ret;

	assert(a);

	c->server_mode = false;

	/* Close socket if already opened */
	if (c->socket_fd != -1) {
		pnp_warn("Socket already opened");
		if (close(c->socket_fd) == -1) {
			pnp_warn("Close socket");
			errno = 0;
		}
		c->socket_fd = -1;
	}

	/* Set hints */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = 0;

	/* Get address list for hostname */
	ret = getaddrinfo(a->hostname, a->port, &hints, &addr_result);
	if (ret != 0) {
		pnp_err("getaddrinfo (address:%s port:%s): %s", a->hostname,
			a->port,
			gai_strerror(ret));
		return false;
	}

	/* Try to connect to some address from address list */
	for (addr_p = addr_result; addr_p != NULL; addr_p = addr_p->ai_next) {
		c->socket_fd = socket(addr_p->ai_family, addr_p->ai_socktype | SOCK_NONBLOCK,
				      addr_p->ai_protocol);

		/* Trying to connect */
		pnp_info("Trying to connect... (address: %s port: %s)", a->hostname, a->port);

		/* Check if socket socket creation was successful */
		if (c->socket_fd == -1) {
			pnp_warn("Cannot create socket. Trying another address.");
			continue;
		}

		/* Try to connect to address */
		if ((ret = connect(c->socket_fd, addr_p->ai_addr, addr_p->ai_addrlen)) != -1)
			break;

		if (ret < 0 && errno == EINPROGRESS) {
			if (wait_for_connection(c))
				break;
		}

		/* Connection was not successful so close socket and try another
		 * address */
		close(c->socket_fd);
		c->socket_fd = -1;
	}

	/* Free addrinfo resources */
	freeaddrinfo(addr_result);

	/* Check if we are connected successfully */
	if (c->socket_fd == -1) {
		pnp_warn("Connection to address '%s:%s' failed", a->hostname, a->port);
		goto connection_failed;
	}

	/* handle SSL */
	if (c->io->connect) {
		if (c->io->connect(c) < 0)
			goto close_connection;
	}

	/* We are successfully connected */
	pnp_connection_set_state(c, PNP_CONNECTED);
	/* We are successfully connected */
	pnp_info("Successfully connected! (address: %s port: %s)", a->hostname, a->port);
	return true;

close_connection:
	pnp_connection_close(c);

connection_failed:
	pnp_connection_set_state(c, PNP_CONNECTION_FAILED);

	return false;
}

/**
 * @brief Start PnP connection server handler
 *
 * Function creates several sockets available for proxying data.
 *
 * @param c       PnP connection object
 * @retval true   Successfully created server threads
 * @retval false  Failed to create server threads
 */
bool pnp_connection_start_proxy_servers(struct pnp_connection *c)
{
	int s_num = c->conf->mp.items_num;
	int s_i;
	int port_in;
	int port_out;

	/* Start servers for all addresses in  */
	for (s_i = 0; s_i < s_num; s_i++)
		if (c->proxy.server[s_i].listen_fd == -1) {
			port_in = pnp_mapport_get_in(&c->conf->mp, s_i, c->conf->serial);
			port_out = pnp_mapport_get_out(&c->conf->mp, s_i);
			c->proxy.server[s_i].port_in = port_in;
			c->proxy.server[s_i].port_out = port_out;
			pnp_connection_proxy_server_start(&c->proxy.server[s_i]);
		}

	return true;
}

/**
 * @brief Process one step of PnP connection
 *
 * This is a main function for processing PnP connection input and output
 * data. It reads and writes from PnP connection socket, processes received
 * data and commands, as well as manages PnP channels (data, new connections,
 * etc.).
 *
 * @param c  PnP connection object
 */
static void pnp_connection_step(struct pnp_connection *c, sigset_t *smsk)
{
	fd_set r_fds, w_fds;
	int maxfd = c->socket_fd;
	int channel_id;
	int old_channel_idx;
	struct pnp_channel **ch_table = c->ch_con.table;
	int ret;
	struct timespec cur;

	/* Zero all fds */
	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);
	maxfd = 0;

	/* Set fds for new loop */
	if (c->rbuf.size < c->rbuf.maxsize) {
		FD_SET(c->socket_fd, &r_fds);
		maxfd = c->socket_fd;
	}
	if (c->wbuf.size > 0) {
		FD_SET(c->socket_fd, &w_fds);
		maxfd = c->socket_fd;
	}
	pnp_channel_container_set_fds(&c->ch_con, &r_fds, &w_fds, &maxfd);
	pnp_connection_proxy_set_fds(&c->proxy, &r_fds, &maxfd);

	/* Wait specified time for some data */
	ret = pselect(maxfd + 1, &r_fds, &w_fds, NULL, &c->pselect_ts, smsk);
	clock_gettime(CLOCK_MONOTONIC, &cur);
	if (ret <= 0) {
		if (ret < 0) {
			if (errno == EINTR) {
				/* Signal caught - we should continue this loop */
				pnp_info("Interrupted select() call");
			}
			else {
				/* Error has occured - we should close this connection */
				pnp_connection_set_state(c, PNP_DISCONNECTED);
				return;
			}
		}
		else {
			/* Timeout */
#ifdef PNP_DEBUG
			pnp_info("Timeout on select() occured");
#endif
			if (cur.tv_sec > c->last_in + c->conf->pnp_socket_timeout) {
				pnp_err("PnP connection I/O in timeout");
				pnp_connection_set_state(c, PNP_DISCONNECTED);
				return;
			}
			if (cur.tv_sec > c->last_out + c->conf->pnp_socket_timeout) {
				pnp_err("PnP connection I/O out timeout");
				pnp_connection_set_state(c, PNP_DISCONNECTED);
				return;
			}
		}
	}

	/* Maybe send PING */
	if (cur.tv_sec > c->last_ping + c->conf->ping_send_period) {
		pnp_msg_send_ping(c);
		c->last_ping = cur.tv_sec;
	}

	/* Check if there are incoming data from PnP connection */
	if (FD_ISSET(c->socket_fd, &r_fds)) {
		if (!c->io->read(c)) {
			pnp_warn("Other part closed or Failed to read from PnP socket");
			pnp_connection_set_state(c, PNP_DISCONNECTED);
			return;
		}

		c->last_in = cur.tv_sec;
	}

	/* Check if we are ready to send more data within PnP protocol */
	if (FD_ISSET(c->socket_fd, &w_fds)) {
		if (!c->io->write(c)) {
			pnp_err("Failed to write to PnP socket");
			pnp_connection_set_state(c, PNP_DISCONNECTED);
			return;
		}

		c->last_out = cur.tv_sec;
	}

	pnp_connection_update_timeout(c, &cur);

	old_channel_idx = c->ch_con.channel_idx;
	c->process_cmds_continue = true;
	while (c->process_cmds_continue) {
		c->process_cmds_continue = false;

		/* Process incoming data */
		pnp_cmd_client_process_cmds_step(c);

		/* Check channels */
		for (channel_id = c->ch_con.channel_idx; channel_id < PNP_CHANNEL_CONTAINER_TABLE_SIZE; channel_id++) {
			if (ch_table[channel_id]) {
				if (old_channel_idx == c->ch_con.channel_idx)
					c->ch_con.channel_idx = channel_id;
				pnp_channel_step(ch_table[channel_id], &r_fds, &w_fds);
			}
		}
		for (channel_id = 0; channel_id < c->ch_con.channel_idx; channel_id++) {
			if (ch_table[channel_id]) {
				if (old_channel_idx == c->ch_con.channel_idx)
					c->ch_con.channel_idx = channel_id;
				pnp_channel_step(ch_table[channel_id], &r_fds, &w_fds);
			}
		}
	}

	/* Check incoming connections on listening sockets */
	pnp_connection_proxy_step(&c->proxy, &r_fds);
}

/**
 * @brief Process PnP connection in a loop
 *
 * This function is executed for most of the time and exits only when
 * PnP connection had some errors (closed socket, invalid data).
 *
 * @param c  PnP connection object
 */
void pnp_connection_loop(struct pnp_connection *c)
{
	sigset_t smsk;
	struct sigaction sa;
	struct timespec cur;

	/* Ignore SIGUSR1 */
	sa.sa_handler = dummy_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	/* Set loop thread id  */
	c->loop_thread = pthread_self();

	/* Set sigmask for this thread */
	sigemptyset(&smsk);
	sigaddset(&smsk, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &smsk, NULL);
	sigdelset(&smsk, SIGUSR1);
	sigaction(SIGUSR1, &sa, NULL);

	/* Set up proper I/O and ping timeouts */
	clock_gettime(CLOCK_MONOTONIC, &cur);
	c->last_in = c->last_out = cur.tv_sec;
	c->last_ping = cur.tv_sec;
	pnp_connection_update_timeout(c, &cur);

	while (c->connection_state != PNP_DISCONNECTED
			&& c->connection_state != PNP_REDIRECT_REQUEST
			&& c->connection_state != PNP_CLOSE_REQUEST
			&& c->connection_state != PNP_FORCE_RECONNECT) {
		pnp_connection_step(c, &smsk);
	}
}
