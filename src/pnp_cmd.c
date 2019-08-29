/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_cmd.h"
#include "pnp_hwaddr.h"
#include "pnp_io.h"
#include "pnp_protobuf_utils.h"

#include "proto/packets.pb-c.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

/**
 * @brief Read byte
 *
 * Function waits until one byte is read.
 *
 * @param c PnP connection object
 * @param byte Pointer to byte where data is saved
 * @retval true Successfully received byte
 * @retval false Failed to receive byte
 */
static inline bool pnp_read_byte(struct pnp_connection *c, void *byte)
{
	uint8_t *b = (uint8_t *)byte;
	uint8_t *rbase = c->rbuf.base;

	if (c->rbuf.size < 1) {
		c->rbuf.block = true;
		return false;
	}

	*b = rbase[(c->rbuf.start) % c->rbuf.maxsize];
	c->rbuf.start = (c->rbuf.start + 1) % c->rbuf.maxsize;
	c->rbuf.size--;

	return true;
}

/**
 * @brief Send buffer with specified size
 *
 * Function waits until whole buffer is sent to connection socket.
 *
 * @param c       PnP connection object
 * @param buffer  Pointer to buffer where data is stored
 * @param len     Data buffer size
 * @retval true   Successfully sent buffer
 * @retval false  Failed to send buffer
 */
static bool pnp_write_buffer(struct pnp_connection *c, void *buffer, int len,
		int flags)
{
	int ret;

	while (len > 0) {
		ret = c->io->write_buffer(c, buffer, len, flags);
		if (ret < 0)
			return false;

		len -= ret;
	}

	return true;
}

/**
 * @brief Send PING message
 *
 * Function sends PING message.
 *
 * @param c PnP connection structure
 * @retval true Successfully sent data
 * @retval false Failed to send data
 */
bool pnp_msg_send_ping(struct pnp_connection *c)
{
	uint8_t *wbase = (uint8_t *)c->wbuf.base;

#ifdef PNP_DEBUG
	pnp_info("Send ping!");
#endif

	if (c->wbuf.size >= c->wbuf.maxsize) {
		pnp_err("Failed to send ping because of full wbuf");
		return false;
	}
	wbase[(c->wbuf.start + c->wbuf.size) % c->wbuf.maxsize] = PNP_CMD_PING;
	c->wbuf.size++;

	return true;
}

/**
 * @brief Send HELLO message
 *
 * Function sends HELLO message with serialid field.
 *
 * @param c PnP connection object
 */
bool pnp_msg_send_hello(struct pnp_connection *c)
{
	uint8_t *buffer;
	int payload_len;
	struct pnp_hwaddr_data pnp_hwaddr_data = {};
	HelloPacket msg = HELLO_PACKET__INIT;
	bool success;
	int err;
	size_t size_bytes;

	pnp_info("Send Hello!");

	/* Get camera information from file */
	/* no longer needed
	 msg.has_cameraid = true;
	 msg.cameraid = 1;
	 */
	msg.serialid = c->conf->serial;
	msg.secret = "12345678901234567890123456789012";
	msg.version = EECONNECT_VERSION;

	err = pnp_hwaddr_fetch(&pnp_hwaddr_data);
	if (err)
		pnp_err("Failed to fetch hwaddrs");
	else
		pnp_hwaddr_fill(&pnp_hwaddr_data, &msg);

	payload_len = hello_packet__get_packed_size(&msg);
	size_bytes = pnp_get_encoded_uint_bytes(payload_len);

	buffer = malloc((size_t)(payload_len + 1 + size_bytes));
	if (!buffer) {
		pnp_err("Could not allocate buffer for Hello packet");
		success = false;
		goto release_send_hello;
	}

	*buffer = PNP_CMD_HELLO;
	pnp_encode_uint_as_varint(payload_len, buffer + 1, size_bytes);
	hello_packet__pack(&msg, buffer + 1 + size_bytes);

	success = pnp_write_buffer(c, buffer, payload_len + 1 + size_bytes, 0);

 release_send_hello:
	if (!err)
		pnp_hwaddr_release(&pnp_hwaddr_data);

	free(buffer);

	return success;
}

/**
 * @brief Send DATA message
 *
 * Function sends DATA message with RAW data.
 *
 * @param c           PnP connection object
 * @param channel_id  PnP channel id
 * @param buffer      Pointer to buffer
 * @param buffer_len  Length of data in buffer
 * @param flags       Additional flags fo send(), e.g. MSG_MORE
 */
bool pnp_msg_send_data(struct pnp_connection *c,
		int channel_id, void *buffer, int buffer_len,
		int flags)
{
	uint8_t header[4];
	uint16_t len16 = buffer_len;
	header[0] = PNP_CMD_DATA;
	header[1] = (uint8_t)channel_id;
	header[2] = len16 >> 8;
	header[3] = len16 & 0xFF;

#ifdef PNP_DEBUG
	pnp_info("Send Data! len = %d", buffer_len);
#endif

	/* Send header (cmd + len) */
	if (!pnp_write_buffer(c, header, 4, flags | MSG_MORE)) {
		pnp_err("Failed to send header of DATA cmd");
		return false;
	}

	/* Send data */
	if (!pnp_write_buffer(c, buffer, buffer_len, flags)) {
		pnp_err("Failed to send data of DATA cmd");
		return false;
	}

	return true;
}

/**
 * @brief Send OPENCHANNEL message
 *
 * Function sends OPENCHANNEL message with channel id, ip and port.
 *
 * @param c           PnP connection object
 * @param channel_id  PnP channel id
 * @param ip          IP address
 * @param port        Port number
 * @param flags       Additional flags to send(), e.g. MSG_MORE
 */
bool pnp_msg_send_openchannel(struct pnp_connection *c,
		int channel_id, char *ip, char *port)
{
	OpenChannelPacket msg = OPEN_CHANNEL_PACKET__INIT;
	size_t payload_len;
	uint8_t *sbuffer = NULL;
	uint8_t *buffer;
	uint8_t *wbase = (uint8_t *)c->wbuf.base;
	size_t size_bytes;

	open_channel_packet__init(&msg);
	msg.channelid = channel_id;
	msg.ip = ip;
	msg.port = atoi(port);

	/* Get buffer length */
	payload_len = open_channel_packet__get_packed_size(&msg);
	size_bytes = pnp_get_encoded_uint_bytes(payload_len);

	/* Check if there is enough space in buffer */
	if (c->wbuf.maxsize - c->wbuf.size < payload_len + 1 + size_bytes) {
		return false;
	}

	/* Check if data can be written in one piece */
	if (c->wbuf.maxsize - (c->wbuf.start + c->wbuf.size) % c->wbuf.maxsize
	    < payload_len + 1 + size_bytes) {
		sbuffer = malloc((size_t)(payload_len + 1 + size_bytes));
		if (!sbuffer) {
			pnp_err("Could not allocate buffer for OpenChannel packet");
			return false;
		}
		buffer = sbuffer;
	}
	else {
		buffer = &wbase[(c->wbuf.start + c->wbuf.size) % c->wbuf.maxsize];
	}

	/* Fill the buffer */
	buffer[0] = PNP_CMD_OPENCHANNEL;
	pnp_encode_uint_as_varint(payload_len, buffer + 1, size_bytes);
	open_channel_packet__pack(&msg, buffer + 1 + size_bytes);

	/* Copy data if we used temporary buffer */
	if (sbuffer) {
		size_t i;
		for (i = 0; i < payload_len + 1 + size_bytes; i++) {
			wbase[(c->wbuf.start + c->wbuf.size + i) % c->wbuf.maxsize] = buffer[i];
		}
		free(sbuffer);
	}

	/* Adjust wbuf size */
	c->wbuf.size += (payload_len + 1 + size_bytes);

	pnp_info("OpenChannel %d msg len: %d", channel_id, (int )payload_len);

	return true;
}

/**
 * @brief Send CLOSECHANNEL message
 *
 * Function sends CLOSECHANNEL message with channel id.
 *
 * @param c           PnP connection object
 * @param channel_id  PnP channel id
 * @param flags       Additional flags to send(), e.g. MSG_MORE
 */
bool pnp_msg_send_closechannel(struct pnp_connection *c, int channel_id)
{
	CloseChannelPacket msg = CLOSE_CHANNEL_PACKET__INIT;
	size_t payload_len;
	uint8_t *sbuffer = NULL;
	uint8_t *buffer = sbuffer;
	uint8_t *wbase = (uint8_t *)c->wbuf.base;
	size_t size_bytes;

	msg.channelid = channel_id;

	/* Get buffer length */
	payload_len = close_channel_packet__get_packed_size(&msg);
	size_bytes = pnp_get_encoded_uint_bytes(payload_len);

	/* Check if there is enough space in buffer */
	if (c->wbuf.maxsize - c->wbuf.size < payload_len + 1 + size_bytes) {
		return false;
	}

	/* Check if data can be written in one piece */
	if (c->wbuf.maxsize - (c->wbuf.start + c->wbuf.size) % c->wbuf.maxsize <
	    payload_len + 1 + size_bytes) {
		sbuffer = malloc((size_t)(payload_len + 1 + size_bytes));
		if (!sbuffer) {
			pnp_err("Could not allocate buffer for OpenChannel packet");
			return false;
		}
		buffer = sbuffer;
	}
	else {
		buffer = &wbase[(c->wbuf.start + c->wbuf.size) % c->wbuf.maxsize];
	}

	/* Fill the buffer */
	buffer[0] = PNP_CMD_CLOSECHANNEL;
	pnp_encode_uint_as_varint(payload_len, buffer + 1, size_bytes);
	close_channel_packet__pack(&msg, buffer + 1 + size_bytes);

	/* Copy data if we used temporary buffer */
	if (sbuffer) {
		size_t i;
		for (i = 0; i < payload_len + 1 + size_bytes; i++) {
			wbase[(c->wbuf.start + c->wbuf.size + i) % c->wbuf.maxsize] = buffer[i];
		}
		free(sbuffer);
	}

	/* Adjust wbuf size */
	c->wbuf.size += (payload_len + 1 + size_bytes);

	pnp_info("Send CloseChannel channelId:%d msg len: %d", channel_id, (int )payload_len);

	/* Close socket that is used identified by channel_id */
//  success = pnp_channel_container_remove(&c->ch_con, channel_id);
//  pnp_info("Channel has been removed from container");
	return true;
}

/**
 * @brief Send REDIRECT message
 *
 * Function sends REDIRECT message with ip and port.
 *
 * @param c      PnP connection object
 * @param ip     IP address
 * @param port   Port number
 * @param flags  Additional flags to send(), e.g. MSG_MORE
 */
bool pnp_msg_send_redirect(struct pnp_connection *c, char *ip, char *port, int flags)
{
	RedirectPacket msg = REDIRECT_PACKET__INIT;
	int payload_len;
	uint8_t *buffer;

	msg.ip = ip;
	msg.port = atoi(port);

	payload_len = redirect_packet__get_packed_size(&msg);
	buffer = (uint8_t*)malloc(payload_len + 2);

	if (buffer == NULL) {
		pnp_err("Failed to allocate buffer of CLOSECHANNEL cmd");
		return false;
	}

	buffer[0] = PNP_CMD_CLOSECHANNEL;
	buffer[1] = (uint8_t)payload_len;

	redirect_packet__pack(&msg, buffer + 2);

	pnp_info("Redirect %s:%d msg len: %d", msg.ip, msg.port, payload_len);

	/* Send buffer */
	if (!pnp_write_buffer(c, buffer, payload_len + 2, flags)) {
		pnp_err("Failed to send buffer of CLOSECHANNEL cmd");
		free(buffer);
		return false;
	}

	free(buffer);
	return true;
}

/**
 * @brief Handle REDIRECT command
 *
 * Receive length and protobuf encoded data, save redirect address information
 * and change current connection state.
 *
 * @param c PnP connection structure
 * @retval true Successfully received redirect address data
 * @retval false Failed to receive redirect address data
 *
 * @post When successful #redirect_address and #connection_state
 *       are updated
 */
static bool pnp_cmd_handle_redirect(struct pnp_connection *c)
{
	uint8_t payload_len;
	uint8_t sbuffer[256];
	uint8_t *buffer = sbuffer;
	RedirectPacket *msg;
	uint8_t *rbase = c->rbuf.base;
	bool ret = false;

	/* Check length */
	if (c->rbuf.size < 2) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_REDIRECT;
		return false;
	}

	/* Read request length */
	payload_len = rbase[(c->rbuf.start) % c->rbuf.maxsize];

	pnp_info("Redirect packet len: %d", (int ) payload_len);

	/* Check length and remove 1 byte from rbuf */
	if (c->rbuf.size - 1 < payload_len) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_REDIRECT;
		return false;
	}
	c->rbuf.start = (c->rbuf.start + 1) % c->rbuf.maxsize;
	c->rbuf.size--;

	/* Set buffer and remove data from rbuf */
	if (c->rbuf.maxsize - c->rbuf.start < payload_len) {
		size_t i;
		buffer = sbuffer;
		for (i = 0; i < payload_len; i++) {
			buffer[i] = rbase[(c->rbuf.start + i) % c->rbuf.maxsize];
		}
	}
	else {
		buffer = &rbase[c->rbuf.start];
	}

	/* Deserialize data */
	msg = redirect_packet__unpack(NULL, payload_len, buffer);
	c->rbuf.start = (c->rbuf.start + payload_len) % c->rbuf.maxsize;
	c->rbuf.size -= payload_len;

	pnp_info("Redirect packet received: ip:%s port:%d", msg->ip, msg->port);

	/* Save information about redirection */
	pnp_address_release(c->redirect_address);
	c->redirect_address = pnp_address_new_ip_port(msg->ip, msg->port);
	if (!c->redirect_address) {
		pnp_err("Failed allocating memory for redirect address");
		goto free_packet;
	}

	pnp_connection_set_state(c, PNP_REDIRECT_REQUEST);
	ret = true;

 free_packet:
	/* Free objects */
	redirect_packet__free_unpacked(msg, NULL);

	return ret;
}

/**
 * @brief Handle data command
 *
 * Receive channel id, length and data from PnP protocol
 *
 * @param c PnP connection object
 * @retval true Successfully received data
 * @retval false Failed to receive data
 */
static bool pnp_cmd_handle_data(struct pnp_connection *c)
{
	uint8_t channel_id;
	uint16_t len;
	struct pnp_channel *ch;
	uint8_t *rbase = c->rbuf.base;
	struct pnp_buffer *rbuf = &c->rbuf;
	struct pnp_buffer *wbuf;

	if (c->rbuf.size < 4) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_DATA;
		return false;
	}

	/* Read channel ID + data length */
	channel_id = rbase[(c->rbuf.start) % c->rbuf.maxsize];
	len = (((uint16_t)rbase[(c->rbuf.start + 1) % c->rbuf.maxsize]) << 8)
			| (rbase[(c->rbuf.start + 2) % c->rbuf.maxsize]);
	ch = c->ch_con.table[channel_id];

#ifdef PNP_DEBUG
	pnp_info("Data packet header: channelId:%d len:%d", (int)channel_id, (int)len);
#endif

	if (!ch || ch->closed_ext) {
		if (!ch)
			pnp_err("No such channel id: %d", channel_id);
		else
			pnp_err("Channel id %d has been closed externally",
					channel_id);
		if (c->rbuf.size - 3 < len) {
			c->rbuf.block = true;
			c->cmd_continue = true;
			c->cmd = PNP_CMD_DATA;
			return false;
		}
		c->rbuf.start = (c->rbuf.start + 3 + len) % c->rbuf.maxsize;
		c->rbuf.size -= (3 + len);
		return true;
	}

	/* Check length and remove 3 bytes from rbuf */
	if (c->rbuf.size - 3 < len || (ch->wbuf.maxsize - ch->wbuf.size) < len) {
		if (c->rbuf.size - 3 < len)
			c->rbuf.block = true;
		else
			ch->wbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_DATA;
		return false;
	}
	c->rbuf.start = (c->rbuf.start + 3) % c->rbuf.maxsize;
	c->rbuf.size -= 3;

#ifdef PNP_DEBUG
	pnp_info("[%d:%d] data id", ch->channel_id, ch->debug_data_in_id++);
#endif

	/* Set output buffer */
	wbuf = &ch->wbuf;

	/* Copy connection read buffer to channel write buffer */
	pnp_buffer_copy(rbuf, wbuf, len);

	return true;
}

/**
 * @brief Handle openchannel command
 *
 * Receive channel id, ip and port that will be used to open new connection.
 *
 * @param c PnP connection object
 * @retval true Successfully opened channel
 * @retval false Failed to open channel
 */
static bool pnp_cmd_handle_openchannel(struct pnp_connection *c)
{
	size_t payload_len;
	size_t len_bytes;
	uint8_t sbuffer[256];
	uint8_t *buffer = sbuffer;
	OpenChannelPacket *msg;
	uint8_t *rbase = c->rbuf.base;

	/* Check length */
	if (c->rbuf.size < 2) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_OPENCHANNEL;
		return false;
	}

	/* Read request length */
	len_bytes = pnp_get_size_from_encoded_pnp_buffer(&c->rbuf);
	if ((int) len_bytes == -1) {
		/* It is not possible to decode the length yet. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_OPENCHANNEL;
		return false;
	}

	payload_len = pnp_decode_uint_from_varint_in_pnp_buffer(&c->rbuf);
	if ((int) payload_len == -1) {
		/* It is not possible to decode the length yet. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_OPENCHANNEL;
		return false;
	}

	pnp_info("OpenChannel packet len: %d", (int ) payload_len);

	/* Check length and remove len_bytes from rbuf */
	if (c->rbuf.size - len_bytes < payload_len) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_OPENCHANNEL;
		return false;
	}
	c->rbuf.start = (c->rbuf.start + len_bytes) % c->rbuf.maxsize;
	c->rbuf.size -= len_bytes;

	/* Set buffer and remove data from rbuf */
	if (c->rbuf.maxsize - c->rbuf.start < payload_len) {
		size_t i;
		buffer = sbuffer;
		for (i = 0; i < payload_len; i++) {
			buffer[i] = rbase[(c->rbuf.start + i) % c->rbuf.maxsize];
		}
	}
	else {
		buffer = &rbase[c->rbuf.start];
	}

	/* Deserialize data */
	msg = open_channel_packet__unpack(NULL, payload_len, buffer);
	c->rbuf.start = (c->rbuf.start + payload_len) % c->rbuf.maxsize;
	c->rbuf.size -= payload_len;

	pnp_info("OpenChannel packet received: channelId:%d ip:%s port:%d",
			(int ) msg->channelid, msg->ip, msg->port);

	/* Connect to requested ip:port and save opened socket */
	pnp_channel_container_add(&c->ch_con,
			c,
			&msg->channelid, msg->ip, msg->port);

	/* Free objects */
	open_channel_packet__free_unpacked(msg, NULL);

	return true;
}

/**
 * @brief Handle closechannel command
 *
 * Receive channel id and close requested connection.
 *
 * @param c PnP connection object
 * @retval true Successfully closed channel
 * @retval false Failed to close channel
 */
static bool pnp_cmd_handle_closechannel(struct pnp_connection *c)
{
	size_t payload_len;
	size_t len_bytes;
	uint8_t sbuffer[256];
	uint8_t *buffer = sbuffer;
	CloseChannelPacket *msg;
	uint8_t *rbase = c->rbuf.base;
	struct pnp_channel *ch;

	/* Check length */
	if (c->rbuf.size < 2) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_CLOSECHANNEL;
		return false;
	}

	/* Read request length */
	len_bytes = pnp_get_size_from_encoded_pnp_buffer(&c->rbuf);
	if ((int) len_bytes == -1) {
		/* It is not possible to decode the length yet. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_CLOSECHANNEL;
		return false;
	}

	payload_len = pnp_decode_uint_from_varint_in_pnp_buffer(&c->rbuf);
	if ((int) payload_len == -1) {
		/* It is not possible to decode the length yet. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_CLOSECHANNEL;
		return false;
	}

	pnp_info("CloseChannel packet len: %d", (int ) payload_len);

	/* Check length and remove len_bytes from rbuf */
	if (c->rbuf.size - len_bytes < payload_len) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_CLOSECHANNEL;
		return false;
	}
	c->rbuf.start = (c->rbuf.start + len_bytes) % c->rbuf.maxsize;
	c->rbuf.size -= len_bytes;

	/* Set buffer and remove data from rbuf */
	if (c->rbuf.maxsize - c->rbuf.start < payload_len) {
		size_t i;
		buffer = sbuffer;
		for (i = 0; i < payload_len; i++) {
			buffer[i] = rbase[(c->rbuf.start + i) % c->rbuf.maxsize];
		}
	}
	else {
		buffer = &rbase[c->rbuf.start];
	}

	/* Deserialize data */
	msg = close_channel_packet__unpack(NULL, payload_len, buffer);
	c->rbuf.start = (c->rbuf.start + payload_len) % c->rbuf.maxsize;
	c->rbuf.size -= payload_len;

	pnp_info("CloseChannel packet received: channelId:%d", (int ) msg->channelid);

	ch = c->ch_con.table[msg->channelid];
	/* Close socket that is used identified by channel_id */
	if (ch) {
		/* From now we should ignore all incoming data on this channel,
		 * but continue to send data that is already in channel buffer.
		 * We should also stop transferring data from channel read buffer
		 * to connection write buffer. */
		ch->closed_ext = true;
	}
	//pnp_channel_container_remove(&c->ch_con, msg->channelid);

	/* Free objects */
	close_channel_packet__free_unpacked(msg, NULL);

	return true;
}

/**
 * @brief Handle HELLO command
 *
 * Receive camera id and secret.
 *
 * @param c       PnP connection object
 * @retval true   Successfully registered camera
 * @retval false  Failed to register camera
 */
static bool pnp_cmd_handle_hello(struct pnp_connection *c)
{
	size_t payload_len;
	size_t len_bytes;
	uint8_t sbuffer[256];
	uint8_t *buffer = sbuffer;
	HelloPacket *msg;
	uint8_t *rbase = c->rbuf.base;
	unsigned long i;

	/* Check length */
	if (c->rbuf.size < 2) {
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_HELLO;
		return false;
	}

	/* Read request length */
	len_bytes = pnp_get_size_from_encoded_pnp_buffer(&c->rbuf);
	if ((int) len_bytes == -1) {
		/* It is not possible to decode the length yet. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_HELLO;
		return false;
	}

	payload_len = pnp_decode_uint_from_varint_in_pnp_buffer(&c->rbuf);
	if ((int) payload_len == -1) {
		/* It is not possible to decode the length yet. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_HELLO;
		return false;
	}

	pnp_info("Hello packet len: %d", (int ) payload_len);

	/* Check length and remove len_bytes from rbuf */
	if (c->rbuf.size - len_bytes < payload_len) {
		/* The payload has not been received completely. Wait
		   until it can be completely read. */
		c->rbuf.block = true;
		c->cmd_continue = true;
		c->cmd = PNP_CMD_HELLO;
		return false;
	}
	c->rbuf.start = (c->rbuf.start + len_bytes) % c->rbuf.maxsize;
	c->rbuf.size -= len_bytes;

	/* Set buffer and remove data from rbuf */
	if (c->rbuf.maxsize - c->rbuf.start < payload_len) {
		size_t i;
		buffer = sbuffer;
		for (i = 0; i < payload_len; i++) {
			buffer[i] = rbase[(c->rbuf.start + i) % c->rbuf.maxsize];
		}
	}
	else {
		buffer = &rbase[c->rbuf.start];
	}

	/* Deserialize data */
	msg = hello_packet__unpack(NULL, payload_len, buffer);
	c->rbuf.start = (c->rbuf.start + payload_len) % c->rbuf.maxsize;
	c->rbuf.size -= payload_len;

	pnp_info("Hello packet received: client version:%s, serial_id:%s, secret:%s",
			(char* ) msg->version, msg->serialid, (char* ) msg->secret);

	for (i = 0; i < msg->n_hwids; i++)
		pnp_info("hwIds[%lu] %s -> %s", i,
			msg->hwids[i]->key, msg->hwids[i]->value);

	if (msg->serialid == NULL || msg->secret == NULL) {
		pnp_err("Serial or secret is NULL: %s %s", msg->serialid, msg->secret);
		hello_packet__free_unpacked(msg, NULL);
		return false;
	}

	/* For now we are not verifying camera_id and secret - just save camera_id */
	// TODO We should split configuration to connection specific (camera_id, secret) and global (ping period)
	strncpy(c->conf->serial, msg->serialid, PNP_SERIAL_SIZE);
	c->conf->serial[PNP_SERIAL_SIZE] = '\0';
	// TODO We should redirect in case we are just dispatch server
//  c->connection_state = PNP_REDIRECT_REQUEST;

	/* Start proxy server listening on map_ports */
	pnp_connection_start_proxy_servers(c);

	/* Free objects */
	hello_packet__free_unpacked(msg, NULL);

	return (strcmp(c->conf->serial, "") == 0);
}

void pnp_cmd_client_process_cmds_step(struct pnp_connection *c)
{
	uint8_t cmd = 0;

	/* Read PnP command id */
	while (c->rbuf.block == false) {
		if (c->cmd_continue) {
			cmd = c->cmd;
			c->cmd_continue = false;
		}
		else {
			if (!pnp_read_byte(c, &cmd)) {
				return;
			}
		}

		/* Do appropriate command */
		switch (cmd) {
		case PNP_CMD_PING:
			pnp_info("Received cmd: PING");
			/* Do nothing */
			break;
		case PNP_CMD_REDIRECT:
			pnp_info("Received cmd: REDIRECT");
			if (!c->server_mode) {
				if (!pnp_cmd_handle_redirect(c))
					return;
			}
			else {
				pnp_warn("Server should not receive such command");
				pnp_connection_set_state(c, PNP_DISCONNECTED);
				return;
			}
			break;
		case PNP_CMD_OPENCHANNEL:
			pnp_info("Received cmd: OPENCHANNEL");
			if (!c->server_mode) {
				if (!pnp_cmd_handle_openchannel(c))
					return;
			}
			else {
				pnp_warn("Server should not receive such command");
				pnp_connection_set_state(c, PNP_DISCONNECTED);
				return;
			}
			break;
		case PNP_CMD_CLOSECHANNEL:
			pnp_info("Received cmd: CLOSECHANNEL");
			if (!pnp_cmd_handle_closechannel(c))
				return;
			break;
		case PNP_CMD_DATA:
#ifdef PNP_DEBUG
			pnp_info("Received cmd: DATA");
#endif
			if (!pnp_cmd_handle_data(c))
				return;
			break;
		case PNP_CMD_HELLO:
			pnp_info("Received cmd: HELLO");
			if (!c->server_mode) {
				pnp_warn("Client should not receive such command");
				pnp_connection_set_state(c, PNP_DISCONNECTED);
				return;
			}
			else {
				pnp_cmd_handle_hello(c);
			}
			break;
		default:
			pnp_warn("Received unsupported cmd: %d", cmd);
			pnp_connection_set_state(c, PNP_DISCONNECTED);
			return;
		}
	}
}
