/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <glib.h>
#include <stdio.h>

#include "pnp_protobuf_utils.h"

#define MAX_LENGTH 10  /* Should be more than enough */

struct pnp_encode_case {
	int value;
	int expected_size;
	uint8_t *expected_buffer;
};

struct pnp_decode_case {
	uint8_t input_buffer[MAX_LENGTH];
	int expected_size;
	int expected_value;
};

struct pnp_decode_pnp_buffer_case {
	uint8_t input_buffer[MAX_LENGTH];
	struct pnp_buffer input_pnp_buffer;
	int expected_size;
	int expected_value;
};

static uint8_t *buffer = NULL;

static void test_get_encoded_uint_bytes(gpointer *fixture, gconstpointer user_data)
{
	g_assert_cmpint(pnp_get_encoded_uint_bytes(0), ==, 1);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(1), ==, 1);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(127), ==, 1);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(128), ==, 2);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(300), ==, 2);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(16383), ==, 2);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(16384), ==, 3);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(2097151), ==, 3);
	g_assert_cmpint(pnp_get_encoded_uint_bytes(2097152), ==, 4);
}

static void test_pnp_encode_uint_as_varint(gpointer *fixture, gconstpointer user_data)
{
	int ncases = 3;
	int encoded_size_bytes;
	struct pnp_encode_case cases[ncases];

	cases[0] = (struct pnp_encode_case) {
		.value = 0,
		.expected_size = 1,
	};
	cases[0].expected_buffer = (uint8_t *) malloc(sizeof(uint8_t *) * cases[0].expected_size);
	*(cases[0].expected_buffer) = 0x00;

	cases[1] = (struct pnp_encode_case) {
		.value = 1,
		.expected_size = 1,
	};
	cases[1].expected_buffer = (uint8_t *) malloc(sizeof(uint8_t *) * cases[0].expected_size);
	*(cases[1].expected_buffer) = 0x01;

	cases[2] = (struct pnp_encode_case) {
		.value = 300,
		.expected_size = 2,
	};
	cases[2].expected_buffer = (uint8_t *) malloc(sizeof(uint8_t *) * cases[0].expected_size);
	*(cases[2].expected_buffer) = 0xAC;
	*(cases[2].expected_buffer + 1) = 0x02;

	for(int i=0; i < ncases; i++) {
		memset(buffer, 0, MAX_LENGTH);
		encoded_size_bytes = pnp_encode_uint_as_varint(cases[i].value,
							       buffer,
							       cases[i].expected_size);
		printf("\nCase %d checking encoded: size_bytes=%d... ", i, encoded_size_bytes);
		fflush(stdout);
		g_assert_cmpmem(buffer, encoded_size_bytes, cases[i].expected_buffer, cases[i].expected_size);
		printf("OK ");
		free(cases[i].expected_buffer);
	}
}

static void test_pnp_get_size_from_encoded_buffer(gpointer *fixture, gconstpointer user_data)
{
	int size;
	int ncases = 5;
	struct pnp_decode_case cases[ncases];
	cases[0] = (struct pnp_decode_case) {
		.input_buffer = {0x00},
		.expected_size = 1
	};
	cases[1] = (struct pnp_decode_case) {
		.input_buffer = {0x01},
		.expected_size = 1
	};
	cases[2] = (struct pnp_decode_case) {
		.input_buffer = {0x7F},
		.expected_size = 1
	};
	cases[3] = (struct pnp_decode_case) {
		.input_buffer = {0xAC, 0x02},
		.expected_size = 2
	};
	cases[4] = (struct pnp_decode_case) {
		.expected_size = -1  /* Meaning function returned error */
	};
	memset(cases[4].input_buffer, 0xFF, MAX_LENGTH);

	for(int i=0; i < ncases; i++) {
		printf("\nCase %d checking... ", i);
		fflush(stdout);
		size = pnp_get_size_from_encoded_buffer(cases[i].input_buffer, MAX_LENGTH);
		g_assert_cmpint(size, ==, cases[i].expected_size);
		printf("OK ");
	}
}

static void test_pnp_get_size_from_encoded_pnp_buffer(gpointer *fixture, gconstpointer user_data)
{
	int size;
	int ncases = 7;
	struct pnp_decode_pnp_buffer_case cases[ncases];
	cases[0] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0x00},
		.expected_size = 1
	};
	cases[0].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[0].input_buffer,
		.start = 0,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[1] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0x01},
		.expected_size = 1
	};
	cases[1].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[1].input_buffer,
		.start = 0,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[2] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0x7F},
		.expected_size = 1
	};
	cases[2].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[2].input_buffer,
		.start = 0,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	/* Same case but byte is at the end of the circular buffer */
	cases[3] = (struct pnp_decode_pnp_buffer_case) {
		.expected_size = 1
	};
	memset(cases[3].input_buffer, 0x00, MAX_LENGTH);
	cases[3].input_buffer[MAX_LENGTH - 1] = 0x7F;
	cases[3].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[3].input_buffer,
		.start = MAX_LENGTH - 1,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[4] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0xAC, 0x02},
		.expected_size = 2
	};
	cases[4].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[4].input_buffer,
		.start = 0,
		.size = 2,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	/* Same case but one byte is at the end of the circular buffer
	   and the second at the start. */
	cases[5] = (struct pnp_decode_pnp_buffer_case) {
		.expected_size = 2
	};
	memset(cases[5].input_buffer, 0x00, MAX_LENGTH);
	cases[5].input_buffer[MAX_LENGTH - 1] = 0xAC;
	cases[5].input_buffer[0] = 0x02;
	cases[5].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[5].input_buffer,
		.start = MAX_LENGTH - 1,
		.size = 2,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[6] = (struct pnp_decode_pnp_buffer_case) {
		.expected_size = -1  /* Meaning function returned error */
	};
	memset(cases[6].input_buffer, 0xFF, MAX_LENGTH);
	cases[6].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[6].input_buffer,
		.start = 0,
		.size = MAX_LENGTH,
		.maxsize = MAX_LENGTH,
		.block = false
	};

	for(int i=0; i < ncases; i++) {
		printf("\nCase %d checking... ", i);
		fflush(stdout);
		size = pnp_get_size_from_encoded_pnp_buffer(&cases[i].input_pnp_buffer);
		g_assert_cmpint(size, ==, cases[i].expected_size);
		printf("OK ");
	}
}

static void test_pnp_decode_uint_from_varint(gpointer *fixture, gconstpointer user_data)
{
	int value;
	int ncases = 5;
	struct pnp_decode_case cases[ncases];
	cases[0] = (struct pnp_decode_case) {
		.input_buffer = {0x00},
		.expected_value = 0,
		.expected_size = 1
	};
	cases[1] = (struct pnp_decode_case) {
		.input_buffer = {0x01},
		.expected_size = 1,
		.expected_value = 1
	};
	cases[2] = (struct pnp_decode_case) {
		.input_buffer = {0x7F},
		.expected_size = 1,
		.expected_value = 127
	};
	cases[3] = (struct pnp_decode_case) {
		.input_buffer = {0xAC, 0x02},
		.expected_size = 2,
		.expected_value = 300
	};
	cases[4] = (struct pnp_decode_case) {
		.expected_size = 10,
		.expected_value = -1  /* Meaning function returned error */
	};
	memset(cases[4].input_buffer, 0xFF, MAX_LENGTH);

	for(int i=0; i < ncases; i++) {
		printf("\nCase %d checking... ", i);
		fflush(stdout);
		value = pnp_decode_uint_from_varint(cases[i].input_buffer, MAX_LENGTH);
		g_assert_cmpint(value, ==, cases[i].expected_value);
		printf("OK ");
	}
}

static void test_pnp_decode_uint_from_varint_in_pnp_buffer(gpointer *fixture, gconstpointer user_data)
{
	int value;
	int ncases = 7;
	struct pnp_decode_pnp_buffer_case cases[ncases];
	cases[0] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0x00},
		.expected_value = 0,
		.expected_size = 1
	};
	cases[0].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[0].input_buffer,
		.start = 0,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[1] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0x01},
		.expected_value = 1,
		.expected_size = 1
	};
	cases[1].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[1].input_buffer,
		.start = 0,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[2] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0x7F},
		.expected_value = 127,
		.expected_size = 1
	};
	cases[2].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[2].input_buffer,
		.start = 0,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	/* Same case but byte is at the end of the circular buffer */
	cases[3] = (struct pnp_decode_pnp_buffer_case) {
		.expected_size = 1,
		.expected_value = 127,
	};
	memset(cases[3].input_buffer, 0x00, MAX_LENGTH);
	cases[3].input_buffer[MAX_LENGTH - 1] = 0x7F;
	cases[3].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[3].input_buffer,
		.start = MAX_LENGTH - 1,
		.size = 1,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[4] = (struct pnp_decode_pnp_buffer_case) {
		.input_buffer = {0xAC, 0x02},
		.expected_value = 300,
		.expected_size = 2
	};
	cases[4].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[4].input_buffer,
		.start = 0,
		.size = 2,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	/* Same case but one byte is at the end of the circular buffer
	   and the second at the start. */
	cases[5] = (struct pnp_decode_pnp_buffer_case) {
		.expected_value = 300,
		.expected_size = 2
	};
	memset(cases[5].input_buffer, 0x00, MAX_LENGTH);
	cases[5].input_buffer[MAX_LENGTH - 1] = 0xAC;
	cases[5].input_buffer[0] = 0x02;
	cases[5].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[5].input_buffer,
		.start = MAX_LENGTH - 1,
		.size = 2,
		.maxsize = MAX_LENGTH,
		.block = false
	};
	cases[6] = (struct pnp_decode_pnp_buffer_case) {
		.expected_size = 10,
		.expected_value = -1 /* Meaning function returned error */
	};
	memset(cases[6].input_buffer, 0xFF, MAX_LENGTH);
	cases[6].input_pnp_buffer = (struct pnp_buffer) {
		.base = cases[6].input_buffer,
		.start = 0,
		.size = MAX_LENGTH,
		.maxsize = MAX_LENGTH,
		.block = false
	};

	for(int i=0; i < ncases; i++) {
		printf("\nCase %d checking... ", i);
		fflush(stdout);
		value = pnp_decode_uint_from_varint_in_pnp_buffer(&cases[i].input_pnp_buffer);
		g_assert_cmpint(value, ==, cases[i].expected_value);
		printf("OK ");
	}
}

static void fixture_setup (gpointer *fixture, gconstpointer user_data)
{
	buffer = malloc(MAX_LENGTH * sizeof(uint8_t));
	g_assert(buffer);
}

static void fixture_teardown (gpointer *fixture, gconstpointer user_data)
{
	free(buffer);
}

int main (int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add("/pnp_protobuf_utils/pnp_get_encoded_uint_bytes",
		   gpointer,
		   NULL,
		   NULL,
		   test_get_encoded_uint_bytes,
		   NULL);
	g_test_add("/pnp_protobuf_utils/pnp_encode_uint_as_varint",
		   gpointer,
		   NULL,
		   fixture_setup,
		   test_pnp_encode_uint_as_varint,
		   fixture_teardown);
	g_test_add("/pnp_protobuf_utils/pnp_get_size_from_encoded_buffer",
		   gpointer,
		   NULL,
		   NULL,
		   test_pnp_get_size_from_encoded_buffer,
		   NULL);
	g_test_add("/pnp_protobuf_utils/pnp_get_size_from_encoded_pnp_buffer",
		   gpointer,
		   NULL,
		   NULL,
		   test_pnp_get_size_from_encoded_pnp_buffer,
		   NULL);
	g_test_add("/pnp_protobuf_utils/pnp_decode_uint_from_varint",
		   gpointer,
		   NULL,
		   NULL,
		   test_pnp_decode_uint_from_varint,
		   NULL);
	g_test_add("/pnp_protobuf_utils/pnp_decode_uint_from_varint_in_pnp_buffer",
		   gpointer,
		   NULL,
		   NULL,
		   test_pnp_decode_uint_from_varint_in_pnp_buffer,
		   NULL);
	return g_test_run();
}
