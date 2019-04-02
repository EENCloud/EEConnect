/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_connection.h"
#include "pnp_address.h"
#include "pnp_server_addresses.h"
#include "pnp_cmd.h"
#include "pnp_dbus.h"
#include "pnp_io.h"
#include "client_config.h"
#include "embed.h"

#include <assert.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>

#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#define CLIENT_CERT       "client.cert"
#define CLIENT_KEY        "client.key"
#define CA_CERT           "ca.cert"
#define CLIENT_CERT_PATH  CONFIG_DIR "/" CLIENT_CERT
#define CLIENT_KEY_PATH   CONFIG_DIR "/" CLIENT_KEY
#define CA_CERT_PATH      CONFIG_DIR "/" CA_CERT
struct pnp_connection *c;

static void print_usage_msg(char *app_name)
{
	fprintf(stderr, "usage: %s [--version] [--build] [--embedded] [-D] [-N] [-c CIPHER_LIST]\n", app_name);
	fprintf(stderr, "                   [-e ENGINE] [-r RECONNECT] [-s SERIAL_NUMBER] [-t RETRY]\n");
	fprintf(stderr, "                   [--conn-timeout=TIME] [--ping-interval=TIME] [--ping-timeout=TIME]\n");
	fprintf(stderr, "                   [--ssl-negotiation-maxtime=TIME]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "optional arguments:\n");
	fprintf(stderr, " --version             display EEConnect version information\n");
	fprintf(stderr, " --build               display EEConnect build options\n");
	fprintf(stderr, " --embedded            display EEConnect embedded files content\n");
	fprintf(stderr, " -D                    enable daemon mode\n");
	fprintf(stderr, " -N                    disable SSL encryption\n");
	fprintf(stderr, " -c CIPHER_LIST        openSSL cipher list which can be used for encryption:\n");
	fprintf(stderr, "                       cipher1:cihper2:cipher3: ... :cipherN\n");
	fprintf(stderr, " -e ENGINE             openSSL engine name which will be used\n");
	fprintf(stderr, " -r RECONNECT          define reconnect wait time (in seconds)\n");
	fprintf(stderr, " -s SERIAL_NUMBER      define serial number for this client\n");
	fprintf(stderr, " -t RETRY              define retry wait time (in seconds)\n");
	fprintf(stderr, " --ssl-negotiation-maxtime=TIME maximum time in seconds to wait for SSL negotiation\n");
	fprintf(stderr, " --conn-timeout=TIME   maximal time of waiting for peer connection accept\n");
	fprintf(stderr, " --ping-interval=TIME  sending ping messages interval\n");
	fprintf(stderr, " --ping-timeout=TIME   maximal time of waiting for peer's ping\n");
}

static struct option long_options[] = {
	{"version", no_argument, 0, 'v'},
	{"build", no_argument, 0, 'q'},
	{"embedded", no_argument, 0, 'w'},
	{"ssl-negotiation-maxtime", required_argument, 0, 'l'},
	{"ping-interval", required_argument, 0, 'x'},
	{"ping-timeout", required_argument, 0, 'y'},
	{"conn-timeout", required_argument, 0, 'z'},
	{}
};

static bool ssl_load_engine(char *engine_name)
{
	ENGINE* e;
	ENGINE_load_dynamic();
	e = ENGINE_by_id(engine_name);
	if (e) {
		if (!ENGINE_init(e)) {
			pnp_err("Cannot init %s", engine_name);
			ENGINE_free(e);
		}
		ENGINE_set_default(e, ENGINE_METHOD_ALL & ~ENGINE_METHOD_DIGESTS);
		pnp_info("%s engine successfully enabled", engine_name);
		return true;
	} else {
		pnp_err("Error finding %s ENGINE", engine_name);
		return false;
	}
}

static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	char buf[256];
	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);

	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(ctx);
		pnp_err("Peer certificate verification error %s (%d) %s",
			X509_verify_cert_error_string(err), err, buf);
	} else {
		pnp_info("Peer certificate verified OK %s", buf);
	}

	return preverify_ok;
}

static int ssl_load_files(SSL_CTX *ctx)
{
	int err = 0;

	err = pnp_io_ssl_load_cert(CLIENT_CERT, CLIENT_CERT_PATH, ctx);
	if (err) {
		pnp_err("Cannot load SSL CERT");
		goto exit;
	}

	err = pnp_io_ssl_load_key(CLIENT_KEY, CLIENT_KEY_PATH, ctx);
	if (err) {
		pnp_err("Cannot load SSL KEY");
		goto exit;
	}

	err = pnp_io_ssl_load_ca(CA_CERT, CA_CERT_PATH, ctx);
	if (err) {
		pnp_err("Cannot load SSL CA CERT, peer certificate verification disabled");
		err = 0;
		goto exit;
	} else {
		SSL_CTX_set_verify(ctx,
				SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				ssl_verify_callback);
	}

exit:
	return err;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	int cert_error = X509_STORE_CTX_get_error(ctx);

	if (ok)
		return ok;

	switch (cert_error) {
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CERT_NOT_YET_VALID:
		pnp_warn("%s, continuing anyway", X509_verify_cert_error_string(cert_error));
		return 1;
	}

	pnp_err("%s", X509_verify_cert_error_string(cert_error));

	return 0;
}

static SSL_CTX* ssl_setup_ctx(char *cipher_list)
{
	SSL_CTX *ssl_ctx;
	int err;

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		pnp_err("Cannot create SSL context");
		return NULL;
	}

	SSL_CTX_set_info_callback(ssl_ctx, pnp_io_ssl_info_callback);

	if (cipher_list) {
		if (!SSL_CTX_set_cipher_list(ssl_ctx, cipher_list)) {
			pnp_err("Cannot set any cipher");
			goto free_ssl_ctx;
		}
	}

	err = ssl_load_files(ssl_ctx);
	if (err)
		goto free_ssl_ctx;

	SSL_CTX_set_verify(ssl_ctx, SSL_CTX_get_verify_mode(ssl_ctx), verify_cb);

	return ssl_ctx;

free_ssl_ctx:
	SSL_CTX_free(ssl_ctx);
	return NULL;
}

static void daemonize(void)
{
	pid_t pid, sid;

	/* Fork process */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork\n");
		exit(EXIT_FAILURE);
	}
	/* Exit parent process */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
		fprintf(stderr, "Failed to exit parent process\n");
	}

	/* Change file mode mask */
	umask(0);

	/* Open logs here */

	/* Create new SID for child process - not to be an orphan */
	sid = setsid();
	if (sid < 0) {
		fprintf(stderr, "Failed to setsid\n");
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if (chdir("/") < 0) {
		fprintf(stderr, "Failed to change current directory\n");
		exit(EXIT_FAILURE);
	}

	/* Close standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

static void ignore_sigpipe(void)
{
	struct sigaction sa;

	/* Ignore SIGPIPE */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);
}

static void int_handler(int signal)
{
	(void)signal;
	pnp_debug("int handler %d", signal);
	pnp_connection_set_state(c, PNP_CLOSE_REQUEST);
}

static void handle_sigint(void)
{
	struct sigaction sa;

	sa.sa_handler = int_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGINT, &sa, NULL);
}

int main(int argc, char *argv[])
{
	struct pnp_server_addresses *addresses;
	struct pnp_address *address;
	struct pnp_configuration conf;
	SSL_CTX *ssl_ctx = NULL;
	pnp_io_setup_t pnp_connection_setup_io = pnp_connection_setup_io_plain;
	int address_idx = -1;
	char *ssl_engine = NULL;
	char *cipher_list = NULL;
	bool use_ssl = true;
	bool daemon_mode = false;
	int option_index = 0;
	int opt;
	int retval = 1;
	int err;

	/* Init configuration */
	pnp_configuration_init(&conf);

	/* Read command line arguments */
	while ((opt = getopt_long(argc, argv, "DNc:e:l:r:s:t:",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 'v':
			printf(EECONNECT_VERSION "\n");
			exit(EXIT_SUCCESS);
		case 'q':
			printf(BUILD_OPTIONS "\n");
			exit(EXIT_SUCCESS);
		case 'w':
			embed_file_print_all();
			exit(EXIT_SUCCESS);
		case 'D':
			daemon_mode = true;
			break;
		case 'N':
			use_ssl = false;
			break;
		case 'c':
			cipher_list = optarg;
			break;
		case 'e':
			ssl_engine = optarg;
			break;
		case 'l':
			conf.ssl_negotiation_maxtime = atoi(optarg);
			break;
		case 'r':
			conf.reconnect_wait = atoi(optarg);
			break;
		case 's':
			strncpy(conf.serial, optarg, PNP_SERIAL_SIZE);
			conf.serial[PNP_SERIAL_SIZE] = 0;
			break;
		case 't':
			conf.retry_wait = atoi(optarg);
			break;
		case 'x':
			conf.ping_send_period = atoi(optarg);
			break;
		case 'y':
			conf.pnp_socket_timeout = atoi(optarg);
			break;
		case 'z':
			conf.connect_timeout = atoi(optarg);
			break;
		default:
			print_usage_msg(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* Go to daemon mode? */
	if (daemon_mode) {
		daemonize();
	}

	ignore_sigpipe();

	/* Init SSL */
	if (use_ssl) {
		SSL_load_error_strings();
		SSL_library_init();

		ssl_ctx = ssl_setup_ctx(cipher_list);
		if (!ssl_ctx)
			goto deinit_configuration;

		pnp_connection_setup_io = pnp_connection_setup_io_ssl;

		if (ssl_engine)
			ssl_load_engine(ssl_engine);

		pnp_info("SSL initialized");
	}

	/* Create new connection */
	c = pnp_connection_new();
	if (!c)
		goto release_ssl_ctx;

	if (!client_config_load(&conf)) {
		pnp_err("Failed to load configuration");
		goto release_connection;
	}

	/* Initialize connection */
	if (!pnp_connection_init(c, &conf)) {
		/* Failed to initialize object */
		pnp_err("Failed to initialize connection");
		goto release_connection;
	}

	/* Setup IO */
	err = pnp_connection_setup_io(c, ssl_ctx);
	if (err) {
		pnp_err("Failed to setup I/O for connection");
		goto release_connection;
	}

	/* Initialize DBus */
	if (!dbus_init(c)) {
		pnp_err("Failed to initialize DBus");
		goto release_connection;
	}

	if (!dbus_start(c->dbus)) {
		pnp_err("Failed to start DBus");
		goto release_dbus;
	}

	handle_sigint();
	/* Get server addresses */
	addresses = &conf.sa;

	/* Start with first address */
	address = addresses->address[0];

	while (c->connection_state != PNP_CLOSE_REQUEST) {
		switch (c->connection_state) {
		case PNP_REDIRECT_REQUEST:
			address = c->redirect_address;
			break;
		default:
			// Shift to next address
			address_idx = (address_idx + 1) % addresses->num;
			address = addresses->address[address_idx];
			break;
		}

		if (pnp_connection_connect(c, address)) {
			/* Send hello message */
			if (pnp_msg_send_hello(c)) {
				dbus_connection_state_change(c->dbus, true);
				pnp_connection_loop(c);
			}

			switch (c->connection_state) {
			case PNP_DISCONNECTED:
				dbus_connection_state_change(c->dbus, false);
				/* Wait 10s before reconnect */
				pnp_connection_close(c);
				sleep(conf.reconnect_wait);
				break;
			case PNP_FORCE_RECONNECT:
				dbus_connection_state_change(c->dbus, false);
				pnp_connection_close(c);
				break;
			case PNP_REDIRECT_REQUEST:
				pnp_connection_close(c);
				break;
			default:
				break;
			}
		}
		else {
			sleep(conf.retry_wait);
		}
	}

	pnp_info("PNP client finishing");
	dbus_connection_state_change(c->dbus, false);
	dbus_stop(c->dbus);

	retval = 0;

release_dbus:
	dbus_release(c);

release_connection:
	pnp_connection_release(c);

release_ssl_ctx:
	SSL_CTX_free(ssl_ctx);

deinit_configuration:
	pnp_configuration_deinit(&conf);

	return retval;
}
