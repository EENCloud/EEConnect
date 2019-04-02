/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_HWADDR_H_
#define SRC_PNP_HWADDR_H_

#include "proto/packets.pb-c.h"

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#define HWADDR_MAX	10

struct pnp_hwaddr_data {
	size_t n_hwids;
	HelloPacket__HwIdsEntry hwids[HWADDR_MAX];
	HelloPacket__HwIdsEntry *hwids_p[HWADDR_MAX];
};

int pnp_hwaddr_fetch(struct pnp_hwaddr_data *data);
void pnp_hwaddr_release(struct pnp_hwaddr_data *data);
void pnp_hwaddr_fill(struct pnp_hwaddr_data *data, HelloPacket *msg);

#endif /* SRC_PNP_HWADDR_H_ */
