/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_SRC_SERVER_CONFIG_H_
#define SRC_SRC_SERVER_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pnp_configuration.h"
#include "pnp_common.h"
#include "pnp_server_addresses.h"
#include "pnp_mapport.h"

bool server_config_load(struct pnp_configuration *conf);

#ifdef __cplusplus
}
#endif

#endif /* SRC_SRC_SERVER_CONFIG_H_ */
