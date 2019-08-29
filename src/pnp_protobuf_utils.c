/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "pnp_protobuf_utils.h"

#include <stdbool.h>

size_t pnp_get_encoded_uint_bytes(unsigned int value)
{
	size_t size_bytes = 0;
	bool finished = false;
	do {
		size_bytes++;
		if( value < 128) {
			finished = true;
		}
		else {
			value = value >> 7;
		}
	} while (!finished);

	return size_bytes;
}

size_t pnp_encode_uint_as_varint(unsigned int value, uint8_t *out, size_t max_length)
{
	uint8_t *ptr = out;
	size_t bytes_written = 0;

	/* According to https://developers.google.com/protocol-buffers/docs/encoding
	   a varint is encoded starting from the least significant group of 7
	   bits. The 8th bit is set if there are more bytes to follow. */
	while (bytes_written < max_length) {
		*ptr = (value & 0xFF) | 0x80;
		bytes_written++;
		value = value >> 7;

		if (value > 0) {
			ptr++;
		} else {
			/* Unset the 8th bit in the last byte */
			*ptr = (*ptr & 0x7F);
			break;
		}
	}

	return bytes_written;
}

size_t pnp_get_size_from_encoded_buffer(uint8_t *buffer, size_t max_length)
{
	bool finished = false;
	uint8_t *ptr = buffer;
	size_t size = 0;
	do {
		if( size >= max_length) {
			/* Could not read the whole varint in max_length bytes */
			return -1;
		}

		size++;
		if (*ptr & 0x80) {
			/* Keep going, more bytes should be read */
			ptr++;
		} else {
			finished = true;
		}
	} while (!finished);

	return size;
}

size_t pnp_get_size_from_encoded_pnp_buffer(struct pnp_buffer *buffer)
{
	bool finished = false;
	uint8_t *ptr;
	int ptr_offset = 0;
	size_t size = 0;
	do {
		if (size >= buffer->size) {
			/* Could not read the whole varint */
			return -1;
		}

		ptr = buffer->base + ((buffer->start + ptr_offset) % buffer->maxsize);
		size++;
		if (*ptr & 0x80) {
			/* Keep going, more bytes should be read */
			ptr_offset++;
		} else {
			finished = true;
		}
	} while (!finished);

	return size;
}


size_t pnp_decode_uint_from_varint(uint8_t *buffer, size_t max_length)
{
	uint8_t *ptr = buffer;
	size_t bytes_read = 0;
	int value = 0;
	bool finished = false;

	while (bytes_read < max_length) {
		value += ( (*ptr & 0x7F) << (7 * bytes_read));
		bytes_read++;

		if (*ptr & 0x80) {
			/* Keep going, more bytes should be read */
			ptr++;
		} else {
			finished = true;
			break;
		}
	}

	return finished? value: -1;
}


size_t pnp_decode_uint_from_varint_in_pnp_buffer(struct pnp_buffer *buffer)
{
	uint8_t *ptr;
	int ptr_offset = 0;
	size_t bytes_read = 0;
	int value = 0;
	bool finished = false;

	while (bytes_read < buffer->size) {
		ptr = buffer->base + ((buffer->start + ptr_offset) % buffer->maxsize);

		value += ( (*ptr & 0x7F) << (7 * bytes_read));
		bytes_read++;

		if (*ptr & 0x80) {
			/* Keep going, more bytes should be read */
			ptr_offset++;
		} else {
			finished = true;
			break;
		}
	}

	return finished? value: -1;
}
