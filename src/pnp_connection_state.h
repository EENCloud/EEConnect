/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_CONNECTION_STATE_H_
#define SRC_PNP_CONNECTION_STATE_H_

/* Type definitions -------------------------------------------------------- */

enum pnp_connection_state {
	PNP_UNINITIALIZED,
	PNP_INITIALIZED,
	PNP_DISPATCH_OK,
	PNP_DISPATCH_FAIL,
	PNP_CONNECTED,
	PNP_CONNECTION_FAILED,
	PNP_REDIRECT_REQUEST,
	PNP_DISCONNECTED,
	PNP_CLOSE_REQUEST,
	PNP_FORCE_RECONNECT
};

#endif /* SRC_PNP_CONNECTION_STATE_H_ */
