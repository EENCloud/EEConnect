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
