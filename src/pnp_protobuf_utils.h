/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_PROTOBUF_UTILS_H_
#define SRC_PNP_PROTOBUF_UTILS_H_

#include "pnp_buffer.h"

#include <stdlib.h>
#include <stdint.h>

/**
 * Get the number of bytes needed to encode an unsigned int.
 *
 * In a protobuf varint each byte the first bit is used to convey
 * whether the byte is the last one or not. If the bit is set, it
 * means there are further bytes to come. That means that only 7 bits
 * are used to encode the size.
 *
 * This function returns how many bytes are needed to encode value as
 * a varint.
 */
size_t pnp_get_encoded_uint_bytes(unsigned int value);

/**
 * Encode to out buffer as a varint the value passed as an unsigned
 * int. The function stops if max_length is reached.
 *
 * This function returns the number of bytes written.
 */
size_t pnp_encode_uint_as_varint(unsigned int value, uint8_t *out, size_t max_length);

/**
 * Get the number of bytes used to encode the size of a delimited
 * message from the encoded buffer. Argument max_length is used to
 * stop reading from buffer in order to avoid overflows.
 *
 * This function returns the number of bytes on success, -1 if it
 * could not read the whole varint in max_length bytes.
 */
size_t pnp_get_size_from_encoded_buffer(uint8_t *buffer, size_t max_length);

/**
 * Get the number of bytes used to encode the size of a delimited
 * message from the encoded circular pnp_buffer.
 *
 * This function returns the number of bytes on success, -1 if it
 * could not read the whole varint in the written bytes of the
 * pnp_buffer.
 */
size_t pnp_get_size_from_encoded_pnp_buffer(struct pnp_buffer *buffer);

/**
 * Decode from buffer the varint as an unsigned int. The function
 * stops if max_length is reached to avoid overflows.
 *
 * This function returns the unsigned int value or -1 if it could not
 * read the whole varint in max_length bytes.
 */
size_t pnp_decode_uint_from_varint(uint8_t *buffer, size_t max_length);

/**
 * Decode from the circular pnp_buffer the varint as an unsigned int.
 *
 * This function returns the unsigned int value or -1 if it could not
 * read the whole varint in the written bytes of the pnp_buffer.
 */
size_t pnp_decode_uint_from_varint_in_pnp_buffer(struct pnp_buffer *buffer);

#endif /* SRC_PNP_PROTOBUF_UTILS_H_ */
