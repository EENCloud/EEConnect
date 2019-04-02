/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_connection.h"
#include "pnp_io.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/uio.h>

struct ssl_data {
	SSL_CTX *ssl_ctx;
	SSL *ssl;
};

static int io_ssl_create(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);

	data->ssl = SSL_new(data->ssl_ctx);
	if (!data->ssl) {
		pnp_err("Cannot create SSL structure");
		return -EIO;
	}

	if (!SSL_set_fd(data->ssl, c->socket_fd)) {
		pnp_err("Cannot set SSL fd");
		return -EIO;
	}

	return 0;
}

static int pnp_io_ssl_accept(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);
	int err;

	pnp_info("SSL accept");

	err = io_ssl_create(c);
	if (err)
		return err;

	if (SSL_accept(data->ssl) != 1) {
		pnp_err("Cannot accept SSL");
		return -EIO;
	}

	return 0;
}

static int wait_for_ssl_connection(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);
	struct timespec stop_ts;
	int ret = 0;

	clock_gettime(CLOCK_MONOTONIC, &stop_ts);
	stop_ts.tv_sec += c->conf->ssl_negotiation_maxtime;

	while ((ret = SSL_connect(data->ssl)) < 0) {
		switch (SSL_get_error(data->ssl, ret)) {
		case SSL_ERROR_WANT_READ:
			ret = pnp_connection_wait_for_data(c, &stop_ts, false);
			break;
		case SSL_ERROR_WANT_WRITE:
			ret = pnp_connection_wait_for_data(c, &stop_ts, true);
			break;
		default:
			pnp_warn("Cannot connect SSL");
			return -EIO;
		}

		if (ret <= 0) {
			if (ret < 0) {
				pnp_warn("SSL connection error");
				return -EIO;
			}

			pnp_warn("SSL connection timeout");
			return -ETIMEDOUT;
		}
	}

	if (ret != 1) {
		pnp_warn("SSL connection error");
		return -EIO;
	}

	return 0;
}

static int pnp_io_ssl_connect(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);
	int err;

	pnp_info("SSL connect");

	err = io_ssl_create(c);
	if (err)
		return err;

	err = wait_for_ssl_connection(c);
	if (err)
		return err;

	pnp_info("SSL connected Ver: %s Cipher: %s",
		SSL_get_version(data->ssl),
		SSL_get_cipher_name(data->ssl));

	SSL_set_mode(data->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	//SSL_set_read_ahead(data->ssl, 1);

	return 0;
}

static bool pnp_io_ssl_read(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);
	struct pnp_buffer *buf = &c->rbuf;
	int ret;

	while (buf->size < buf->maxsize) {
		void *base = buf->base + (buf->start + buf->size) % buf->maxsize;
		size_t len = (buf->base + buf->maxsize) - base;

		if ((size_t)(buf->maxsize - buf->size) <= len)
			len = buf->maxsize - buf->size;

#ifdef SSL_DEBUG
		pnp_info("SSL read: base: %p size: %d", base, len);
#endif

		ret = SSL_read(data->ssl, base, len);
		if (ret <= 0) {
			int ssl_err = SSL_get_error(data->ssl, ret);
			switch (ssl_err) {
			case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				return true;
			default:
				pnp_err("SSL read1 error: %d", ssl_err);
				ERR_print_errors_fp(stderr);
				return false;
			}
		}
#ifdef SSL_DEBUG
		pnp_info("SSL read: %d", ret);
#endif

		buf->block = false;
		buf->size += ret;
	}

	return true;
}

static bool pnp_io_ssl_write(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);
	struct pnp_buffer *buf = &c->wbuf;
	int ret;

	while (buf->size > 0) {
		void *base = buf->base + buf->start;
		size_t len = (buf->base + buf->maxsize) - base;

		if ((size_t)(buf->size) <= len)
			len = buf->size;

#ifdef SSL_DEBUG
		pnp_info("SSL write: base: %p size: %d", base, len);
#endif
		ret = SSL_write(data->ssl, base, len);
#ifdef SSL_DEBUG
		pnp_info("SSL wrote: %d", ret);
#endif
		if (ret <= 0) {
			int ssl_err = SSL_get_error(data->ssl, ret);
			switch (ssl_err) {
			case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				return true;
			default:
				pnp_err("SSL write1 error: %d", ssl_err);
				ERR_print_errors_fp(stderr);
				return false;
			}
		}

		buf->block = false;
		buf->start = (buf->start + ret) % buf->maxsize;
		buf->size -= ret;
	}

	return true;
}

static int pnp_io_ssl_write_buffer(struct pnp_connection *c, void *buffer,
				int len, int flags)
{
	struct ssl_data *data = pnp_connection_io_data(c);
	int ret;

retry:
	ret = SSL_write(data->ssl, buffer, len);
	if (ret <= 0) {
		int ssl_err = SSL_get_error(data->ssl, ret);

		switch (ssl_err) {
		case SSL_ERROR_WANT_WRITE:
			goto retry;
		default:
			pnp_err("SSL write error: %d", ssl_err);
			return -EIO;
		}
	}

	return ret;
}

static void pnp_io_ssl_close(struct pnp_connection *c)
{
	struct ssl_data *data = pnp_connection_io_data(c);

	if (!data->ssl)
		return;

	SSL_shutdown(data->ssl);
	SSL_free(data->ssl);
	data->ssl = NULL;
}

static struct pnp_io ssl_io = {
	.accept = pnp_io_ssl_accept,
	.connect = pnp_io_ssl_connect,
	.write_buffer = pnp_io_ssl_write_buffer,
	.read = pnp_io_ssl_read,
	.write = pnp_io_ssl_write,
	.close = pnp_io_ssl_close,
};

void pnp_io_ssl_info_callback(const SSL *s, int where, int ret)
{
	const char *str;
	int w;

	w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT)
		str = "connect";
	else if (w & SSL_ST_ACCEPT)
		str = "accept";
	else
		str = "undefined";

	if (where & SSL_CB_LOOP) {
		pnp_info("SSL %s:%s", str, SSL_state_string_long(s));
	} else if (where & SSL_CB_ALERT) {
		str = (where & SSL_CB_READ) ? "read" : "write";
		pnp_info("SSL alert %s:%s:%s",
			 str,
			 SSL_alert_type_string_long(ret),
			 SSL_alert_desc_string_long(ret));
	} else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			pnp_err("SSL %s:failed in %s",
				str, SSL_state_string_long(s));
		} else if (ret < 0) {
			pnp_err("SSL %s:error in %s",
				str, SSL_state_string_long(s));
		}
	}
}

int pnp_io_ssl_load_cert(const char *structure_name, const char *file_name,
		SSL_CTX *ctx)
{
	BIO *bio;
	struct pnp_file file;
	X509 *cert = NULL;
	int err, ret = -EINVAL;

	err = pnp_file_load(&file, structure_name, file_name);
	if (err)
		return err;

	bio = BIO_new_mem_buf(pnp_file_get_content(&file), -1);
	if (!bio) {
		ret = -ENOMEM;
		goto release_file;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert)
		goto free_bio;

	if (SSL_CTX_use_certificate(ctx, cert) == 1)
		ret = 0;

	X509_free(cert);
free_bio:
	BIO_free(bio);
release_file:
	pnp_file_release(&file);

	return ret;
}

int pnp_io_ssl_load_key(const char *structure_name, const char *file_name,
		SSL_CTX *ctx)
{
	BIO *bio;
	struct pnp_file file;
	EVP_PKEY *pkey = NULL;
	int err, ret = -EINVAL;

	err = pnp_file_load(&file, structure_name, file_name);
	if (err)
		return err;

	bio = BIO_new_mem_buf(pnp_file_get_content(&file), -1);
	if (!bio) {
		ret = -ENOMEM;
		goto release_file;
	}

	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!pkey)
		goto free_bio;

	if (SSL_CTX_use_PrivateKey(ctx, pkey) == 1)
		ret = 0;

	EVP_PKEY_free(pkey);
free_bio:
	BIO_free(bio);
release_file:
	pnp_file_release(&file);

	return ret;
}

int pnp_io_ssl_load_ca(const char *structure_name, const char *file_name,
		SSL_CTX *ctx)
{
	BIO *bio;
	struct pnp_file file;
	X509_STORE *store = NULL;
	X509 *cert = NULL;
	int err, ret = -EINVAL;

	err = pnp_file_load(&file, structure_name, file_name);
	if (err)
		return err;

	bio = BIO_new_mem_buf(pnp_file_get_content(&file), -1);
	if (!bio) {
		ret = -ENOMEM;
		goto release_file;
	}

	store = SSL_CTX_get_cert_store(ctx);
	if (!store)
		goto free_bio;

	while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
		if (X509_STORE_add_cert(store, cert) == 1)
			ret = 0;
	}

free_bio:
	BIO_free(bio);
release_file:
	pnp_file_release(&file);

	return ret;
}

int pnp_connection_setup_io_ssl(struct pnp_connection *c, void *ctx)
{
	struct ssl_data *data;
	int ret = 0;

	data = calloc(1, sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->ssl_ctx = ctx;
	pnp_connection_setup_io(c, &ssl_io, data);

	return ret;
}
