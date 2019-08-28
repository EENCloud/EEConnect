/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_PROTOBUF_UTILS_H_
#define SRC_PNP_PROTOBUF_UTILS_H_

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

#endif /* SRC_PNP_PROTOBUF_UTILS_H_ */
