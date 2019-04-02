/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_COMMON_H_
#define SRC_PNP_COMMON_H_

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define pnp_clean_errno() (errno == 0 ? "None" : strerror(errno))

#if defined(PNP_STDOUT)

#ifdef PNP_DEBUG
#define pnp_debug(M, ...) printf("[DEBUG] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#else
#define pnp_debug(M, ...)
#endif
#define pnp_err(M, ...) printf("[ERROR] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#define pnp_warn(M, ...) printf("[WARN] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#define pnp_info(M, ...) printf("[INFO] " M "\n", ##__VA_ARGS__)

#elif defined(PNP_STDERR)

#ifdef PNP_DEBUG
#define pnp_debug(M, ...) fprintf(stderr, "[DEBUG] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#else
#define pnp_debug(M, ...)
#endif
#define pnp_err(M, ...) fprintf(stderr, "[ERROR] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#define pnp_warn(M, ...) fprintf(stderr, "[WARN] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#define pnp_info(M, ...) fprintf(stderr, "[INFO] " M "\n", ##__VA_ARGS__)

#elif defined(PNP_SYSLOG)

#ifdef PNP_DEBUG
#define pnp_debug(M, ...) syslog(LOG_DEBUG, "[DEBUG] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#else
#define pnp_debug(M, ...)
#endif
#define pnp_err(M, ...) syslog(LOG_ERR, "[ERROR] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#define pnp_warn(M, ...) syslog(LOG_WARNING, "[WARN] (errno: %s) " M "\n", pnp_clean_errno(), ##__VA_ARGS__)
#define pnp_info(M, ...) syslog(LOG_INFO, "[INFO] " M "\n", ##__VA_ARGS__)

#else

static inline void pnp_debug(const char *fmt, ...) {}
static inline void pnp_err(const char *fmt, ...) {}
static inline void pnp_warn(const char *fmt, ...) {}
static inline void pnp_info(const char *fmt, ...) {}

#endif

#define pnp_check(A, M, ...) if(!(A)) { pnp_err(M, ##__VA_ARGS__); errno=0; goto error; }
#define pnp_sentinel(M, ...)  { pnp_err(M, ##__VA_ARGS__); errno=0; goto error; }
#define pnp_check_mem(A) pnp_check((A), "Out of memory.")

static inline int err_from_errno(void)
{
	int err = -errno;

	errno = 0;

	return err;
}

#endif /* SRC_PNP_COMMON_H_ */
