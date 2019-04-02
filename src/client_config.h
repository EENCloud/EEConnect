/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_SRC_CLIENT_CONFIG_H_
#define SRC_SRC_CLIENT_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pnp_configuration.h"
#include "pnp_common.h"
#include "pnp_server_addresses.h"

bool client_config_load(struct pnp_configuration *conf);

#ifdef __cplusplus
}
#endif

#endif /* SRC_SRC_CLIENT_CONFIG_H_ */
