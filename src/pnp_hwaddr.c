/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pnp_hwaddr.h"
#include "pnp_common.h"

#include <time.h>

static int mnl_fill_hwaddr(HelloPacket__HwIdsEntry *entry, struct nlattr *attr)
{
	uint8_t *hwaddr = mnl_attr_get_payload(attr);
	size_t hwaddr_len = mnl_attr_get_payload_len(attr);
	size_t i;
	char *buf;
	size_t buf_size = 256;
	int written;
	char *fmt = "%.2x";

	if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
		return MNL_CB_ERROR;

	if (hwaddr_len == 0) {
		pnp_err("hwaddr_len == 0");
		return MNL_CB_OK;
	}

	buf = malloc(buf_size);
	if (!buf) {
		pnp_err("Failed to allocate buffer");
		return MNL_CB_OK;
	}

	entry->value = buf;

	for (i = 0; i < hwaddr_len; i++) {
		written = snprintf(buf, buf_size, fmt, hwaddr[i] & 0xff);
		if (written < 0 || (size_t) written >= buf_size) {
			buf[buf_size - 1] = '\0';
			return MNL_CB_OK;
		}

		buf += written;
		buf_size -= written;
		fmt = ":%.2x";
	}

	return MNL_CB_OK;
}

static int mnl_data_cb(const struct nlmsghdr *nlh, void *user_data)
{
	struct pnp_hwaddr_data *data = user_data;
	HelloPacket__HwIdsEntry *entry = &data->hwids[data->n_hwids];
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *attr;
	int ret;

	if (data->n_hwids >= HWADDR_MAX)
		return MNL_CB_OK;

	if (ifm->ifi_type != ARPHRD_ETHER)
		return MNL_CB_OK;

	hello_packet__hw_ids_entry__init(entry);

	mnl_attr_for_each(attr, nlh, sizeof(*ifm)) {
		int type = mnl_attr_get_type(attr);

		/* skip unsupported attribute in user-space */
		if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
			continue;

		switch(type) {
		case IFLA_IFNAME:
			if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
				return MNL_CB_ERROR;

			entry->key = strdup(mnl_attr_get_str(attr));
			break;
		case IFLA_ADDRESS:
			ret = mnl_fill_hwaddr(entry, attr);
			if (ret != MNL_CB_OK)
				return ret;
			break;
		}
	}

	data->hwids_p[data->n_hwids] = entry;
	data->n_hwids++;

	return MNL_CB_OK;
}

int pnp_hwaddr_fetch(struct pnp_hwaddr_data *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	unsigned int seq, portid;
	int ret;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);

	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(*rt));
	rt->rtgen_family = AF_PACKET;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl)
		return err_from_errno();

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		ret = -errno;
		errno = 0;
		goto close_socket;
	}

	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		ret = -errno;
		errno = 0;
		goto close_socket;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, mnl_data_cb, data);
		if (ret <= MNL_CB_STOP)
			break;

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if (ret == -1) {
		ret = -errno;
		errno = 0;
		goto free_data;
	}

	mnl_socket_close(nl);

	return 0;

free_data:
	pnp_hwaddr_release(data);
close_socket:
	mnl_socket_close(nl);

	return ret;
}

void pnp_hwaddr_release(struct pnp_hwaddr_data *data)
{
	size_t i;

	for (i = 0; i < data->n_hwids; i++) {
		HelloPacket__HwIdsEntry *entry = &data->hwids[i];

		free(entry->key);
		free(entry->value);
	}
}

void pnp_hwaddr_fill(struct pnp_hwaddr_data *data, HelloPacket *msg)
{
	msg->hwids = data->hwids_p;
	msg->n_hwids = data->n_hwids;
}
