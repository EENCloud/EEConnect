/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_connection.h"
#include "pnp_address.h"
#include "pnp_server_addresses.h"
#include "pnp_cmd.h"
#include "pnp_thread_helper.h"
#include "pnp_io.h"
#include "server_config.h"

#include <assert.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <string.h>

#include <netdb.h>
#include <signal.h>
#include <openssl/ssl.h>

#define SERVER_CERT       "server.cert"
#define SERVER_KEY        "server.key"
#define SERVER_CERT_PATH  CONFIG_DIR "/" SERVER_CERT
#define SERVER_KEY_PATH   CONFIG_DIR "/" SERVER_KEY
#define DEFAULT_PORT "18080"
#define DEFAULT_HOSTNAME "0.0.0.0"

static bool server_thread_start(struct pnp_connection *c);
static void *server_thread(void *data);

static int opt;

static void print_usage_msg(char *app_name)
{
	fprintf(stderr, "usage: %s [-N] [-p PORT] [--ping-interval=TIME]\n", app_name);
	fprintf(stderr, "                   [--ping-timeout=TIME]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "optional arguments:\n");
	fprintf(stderr, " -N                    disable SSL encryption\n");
	fprintf(stderr, " -p PORT               set server port\n");
	fprintf(stderr, " --ping-interval=TIME  sending ping messages interval\n");
	fprintf(stderr, " --ping-timeout=TIME   maximal time of waiting for peer's ping\n");
}

static struct option long_options[] = {
	{"ping-interval", required_argument, 0, 'x'},
	{"ping-timeout", required_argument, 0, 'y'},
	{}
};

static void ignore_sigpipe(void)
{
	struct sigaction sa;

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);
}

static int ssl_load_files(SSL_CTX *ctx)
{
	int err = 0;

	err = pnp_io_ssl_load_cert(SERVER_CERT, SERVER_CERT_PATH, ctx);
	if (err) {
		pnp_err("Cannot load SSL CERT");
		goto exit;
	}

	err = pnp_io_ssl_load_key(SERVER_KEY, SERVER_KEY_PATH, ctx);
	if (err) {
		pnp_err("Cannot load SSL KEY");
		goto exit;
	}

exit:
	return err;
}

static SSL_CTX* ssl_setup_ctx()
{
	SSL_CTX *ssl_ctx;
	int err;

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		pnp_err("Cannot create SSL context");
		return NULL;
	}

	SSL_CTX_set_info_callback(ssl_ctx, pnp_io_ssl_info_callback);

	err = ssl_load_files(ssl_ctx);
	if (err)
		goto free_ssl_ctx;

	return ssl_ctx;

free_ssl_ctx:
	SSL_CTX_free(ssl_ctx);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct pnp_configuration conf;
	struct addrinfo *addr_result, *addr_p;
	struct addrinfo hints;
	SSL_CTX *ssl_ctx = NULL;
	pnp_io_setup_t pnp_connection_setup_io = pnp_connection_setup_io_plain;
	int ret;
	int listen_fd = -1;
	int af = AF_INET;
	char s_port_in[8] = DEFAULT_PORT;
	int reuse = 1;
	bool use_ssl = true;
	int option_index = 0;

	pnp_configuration_init(&conf);

	/* Read command line arguments */
	while ((opt = getopt_long(argc, argv, "Np:",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 'N':
			use_ssl = false;
			break;
		case 'p':
			strncpy(s_port_in, optarg, 8);
			s_port_in[7] = '\0';
			break;
		case 'x':
			conf.ping_send_period = atoi(optarg);
			break;
		case 'y':
			conf.pnp_socket_timeout = atoi(optarg);
			break;
		default:
			print_usage_msg(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	ignore_sigpipe();

	/* Read configuration */
	if (!server_config_load(&conf)) {
		pnp_err("Failed to load configuration");
		return false;
	}

	/* Init SSL library */
	if (use_ssl) {
		SSL_load_error_strings();
		SSL_library_init();

		ssl_ctx = ssl_setup_ctx();
		if (!ssl_ctx)
			return false;

		pnp_connection_setup_io = pnp_connection_setup_io_ssl;
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

	/* Get address list for hostname */
	ret = getaddrinfo(DEFAULT_HOSTNAME, s_port_in, &hints, &addr_result);
	if (ret != 0) {
		pnp_err("getaddrinfo (port:%s): %s", s_port_in,
				gai_strerror(ret));
		return false;
	}

	/* Try to connect to some address from address list */
	for (addr_p = addr_result; addr_p != NULL; addr_p = addr_p->ai_next) {
		listen_fd = socket(addr_p->ai_family, addr_p->ai_socktype,
				addr_p->ai_protocol);

		/* Check if socket socket creation was successful */
		if (listen_fd == -1) {
			pnp_warn("Socket == -1. Trying another address.");
			continue;
		}

		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
		/* Try to bind to address */
		if ((ret = bind(listen_fd, addr_p->ai_addr, addr_p->ai_addrlen)) != -1) {
			/* We are successfully bind */
			pnp_info("Successfully bind() on port %s!", s_port_in);
			af = addr_p->ai_family;
			break;
		}

		/* Connection was not successful so close socket and try another
		 * address */
		close(listen_fd);
		listen_fd = -1;
	}

	/* Free addrinfo resources */
	freeaddrinfo(addr_result);

	/* Check if we are connected successfully */
	if (listen_fd == -1) {
		pnp_warn("Bind to port '%s' failed", s_port_in);
		return false;
	}

	/* Listen with 5 queued connections */
	listen(listen_fd, 5);

	/* Accept connections */
	while (1) {
		struct pnp_connection *c;
		int err;

		pnp_info("Before accept");
		err = pnp_connection_accept(&c, listen_fd, af, &conf,
					pnp_connection_setup_io, ssl_ctx);
		pnp_info("After accept");
		if (err)
			continue;

		server_thread_start(c);
	}

	SSL_CTX_free(ssl_ctx);
	pnp_configuration_deinit(&conf);
}

static bool server_thread_start(struct pnp_connection *c)
{
	pthread_t thid;

	if (!pnp_thread_create_detached(&thid, server_thread, c)) {
		pnp_err("Failed to create PnP server thread");
		pnp_connection_release(c);
		return false;
	}

	return true;
}

static void *server_thread(void *data)
{
	struct pnp_connection *c = data;
	int address_idx;
	struct pnp_address *a;

	/* Process commands */
	pnp_connection_loop(c);

	switch (c->connection_state) {
	case PNP_REDIRECT_REQUEST:
		/* Send redirection in case camera has registered successfully */
		if (c->conf->sa.num == 0)
			goto release_connection;

		address_idx = 0;

		a = c->conf->sa.address[address_idx];
		pnp_msg_send_redirect(c, a->hostname, a->port, 0);
		break;
	default:
		break;
	}

release_connection:
	/* Close PnP connection */
	pnp_connection_release(c);

	return NULL;
}
