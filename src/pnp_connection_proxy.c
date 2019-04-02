/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_connection_proxy.h"
#include "pnp_cmd.h"

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* Static functions -------------------------------------------------------- */

/* Global functions -------------------------------------------------------- */

/**
 * @brief Initialize proxy object for a PnP connection
 *
 * @param proxy  Proxy object of a PnP connection
 * @param c      PnP connection object
 * @retval true  Successfully initialized proxy object
 * @retval false Failed to initialize proxy object
 */
bool pnp_connection_proxy_init(struct pnp_connection_proxy *proxy,
		struct pnp_connection *c)
{
	int i;

	for (i = 0; i < PNP_CONNECTION_PROXY_SERVERS; i++) {
		proxy->server[i].c = c;
		proxy->server[i].state = PNP_THREAD_INITIALIZED;
		proxy->server[i].listen_fd = -1;
		proxy->server[i].af = AF_INET;
	}

	return true;
}

/**
 * @brief Close all proxy servers for a PnP connection
 *
 * @param proxy  Proxy object of a PnP connection
 * @retval true  Successfully stopped all proxy servers
 * @retval false Failed to stop proxy servers
 */
bool pnp_connection_proxy_close(struct pnp_connection_proxy *proxy)
{
	int i;

	for (i = 0; i < PNP_CONNECTION_PROXY_SERVERS; i++) {
		pnp_connection_proxy_server_stop(&proxy->server[i]);
	}

	return true;
}

/**
 * @brief Release proxy object of a PnP connection
 *
 * @param proxy  Proxy object of a PnP connection
 * @retval true  Successfully released object
 * @retval false Failed to release object
 */
bool pnp_connection_proxy_release(struct pnp_connection_proxy *proxy)
{
	pnp_connection_proxy_close(proxy);

	return true;
}

/**
 * @brief Start in new thread proxy server for a PnP connection
 *
 * @param serv PnP connection server proxy object
 * @retval true  Successfully started proxy server in new thread
 * @retval false Failed to start proxy server in new thread
 */
bool pnp_connection_proxy_server_start(struct pnp_connection_proxy_server *serv)
{
	struct addrinfo *addr_result, *addr_p;
	struct addrinfo hints;
	char s_port_in[8];
	char s_port_out[8];
	int ret;
	int reuse = 1;
	int fcntl_flags;

	if (serv->listen_fd > -1) {
		pnp_warn("PnP connection proxy is already running %d -> %d",
				serv->port_in, serv->port_out);
		return false;
	}

	/* Set hints */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	/* Get string from integer port */
	sprintf(s_port_in, "%d", serv->port_in);
	sprintf(s_port_out, "%d", serv->port_out);

	/* Get address list for hostname */
	ret = getaddrinfo(NULL, s_port_in, &hints, &addr_result);
	if (ret != 0) {
		pnp_err("getaddrinfo (port:%s): %s", s_port_in,
				gai_strerror(ret));
		return false;
	}

	/* Try to connect to some address from address list */
	for (addr_p = addr_result; addr_p != NULL; addr_p = addr_p->ai_next) {
		serv->listen_fd = socket(addr_p->ai_family, addr_p->ai_socktype,
				addr_p->ai_protocol);

		/* Check if socket socket creation was successful */
		if (serv->listen_fd == -1) {
			pnp_warn("Socket == -1. Trying another address.");
			continue;
		}

		/* Try to bind to address */
		setsockopt(serv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
		if ((ret = bind(serv->listen_fd, addr_p->ai_addr, addr_p->ai_addrlen)) != -1) {
			/* We are successfully bind */
			pnp_info("Successfully bind() on port %s!", s_port_in);
			serv->af = addr_p->ai_family;
			break;
		}

		/* Connection was not successful so close socket and try another
		 * address */
		close(serv->listen_fd);
		serv->listen_fd = -1;
	}

	/* Free addrinfo resources */
	freeaddrinfo(addr_result);

	/* Check if we are connected successfully */
	if (serv->listen_fd == -1) {
		pnp_warn("Bind to port '%s' failed", s_port_in);
		return false;
	}

	/* Listen with 5 queued connections */
	listen(serv->listen_fd, 5);

	/* Set nonblocking operations on accept(listen_fd) */
	fcntl_flags = fcntl(serv->listen_fd, F_GETFL, 0);
	fcntl_flags |= O_NONBLOCK;
	fcntl(serv->listen_fd, F_SETFL, fcntl_flags);

	return true;
}

/**
 * @brief Stop proxy server for a PnP connection
 *
 * @param serv PnP connection server proxy object
 */
void pnp_connection_proxy_server_stop(struct pnp_connection_proxy_server *serv)
{
	if (serv->listen_fd > -1) {
		pnp_info("Channel proxy server is shutting down %d -> %d",
			 serv->port_in,
			 serv->port_out);

		/* Close listening socket */
		close(serv->listen_fd);
		serv->listen_fd = -1;
	}
}

/**
 * @brief Set fd_set for all active proxy servers
 *
 * @param proxy PnP connection server proxy object
 * @param fds   Pointer to fd_set structure
 * @param maxfd Pointer to maximum file descriptor value, which may be updated
 */
void pnp_connection_proxy_set_fds(struct pnp_connection_proxy *proxy,
		fd_set *fds, int *maxfd)
{
	int i;

	for (i = 0; i < PNP_CONNECTION_PROXY_SERVERS; i++) {
		if (proxy->server[i].listen_fd != -1) {
			FD_SET(proxy->server[i].listen_fd, fds);
			if (proxy->server[i].listen_fd > *maxfd)
				*maxfd = proxy->server[i].listen_fd;
		}
	}
}

/**
 * @brief Step through all proxy servers and serve incoming connections
 *
 * @param proxy PnP connection server proxy object
 * @param fds   Pointer to fd_set structure returned from select() function
 * @retval true  Successfully stepped through all proxy servers
 * @retval false Failed to accept connection from at least 1 proxy server
 */
bool pnp_connection_proxy_step(struct pnp_connection_proxy *proxy, fd_set *fds)
{
	int i;
	bool success = true;

	for (i = 0; i < PNP_CONNECTION_PROXY_SERVERS; i++) {
		if (proxy->server[i].listen_fd != -1 && FD_ISSET(proxy->server[i].listen_fd, fds))
			if (!pnp_connection_proxy_server_step(&proxy->server[i]))
				success = false;
	}

	return success;
}

/**
 * @brief Try to accept connection on proxy server and create new channel
 *
 * @param serv   PnP proxy server object
 * @retval true  Successfully accepted connection and created new channel
 * @retval false Failed to accept connection or create new channel
 */
bool pnp_connection_proxy_server_step(struct pnp_connection_proxy_server *serv)
{
	struct pnp_connection *c = (struct pnp_connection *)serv->c;
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addrlen = sizeof(struct sockaddr);
	int fcntl_flags;
	char str[INET6_ADDRSTRLEN];
	int channel_id;
	char s_port_in[8];
	char s_port_out[8];

	/* Get string from integer port */
	sprintf(s_port_in, "%d", serv->port_in);
	sprintf(s_port_out, "%d", serv->port_out);

	/* Non-blocking accept */
	client_fd = accept(serv->listen_fd, (struct sockaddr *)&client_addr,
			&client_addrlen);

	if (client_fd < 0) {
		pnp_err("Error on accepting connection on port %s", s_port_in);
		errno = 0;
		return false;
	}

	/* Set nonblocking operations */
	fcntl_flags = fcntl(client_fd, F_GETFL, 0);
	fcntl_flags |= O_NONBLOCK;
	fcntl(client_fd, F_SETFL, fcntl_flags);

	inet_ntop(serv->af, (const void *)&client_addr.sin_addr, str,
	INET6_ADDRSTRLEN);
	pnp_info("Accepted connection from %s:%d", str,
			(int ) ntohs(client_addr.sin_port));

	/* Create child thread (-1 means first available channel_id,
	 * NULL means that we are already connected) */
	channel_id = -1;
	if (pnp_channel_container_add(&c->ch_con, c, &channel_id,
	NULL, client_fd)) {
		if (!pnp_msg_send_openchannel(c, channel_id, "127.0.0.1", s_port_out)) {
			pnp_err("Failed to send openchannel");
			pnp_channel_container_remove(&c->ch_con, channel_id);
			return false;
		}
	}

	return true;
}
