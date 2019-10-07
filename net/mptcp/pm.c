// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

/* path manager command handlers */

int mptcp_pm_announce_addr(u32 token, u8 local_id, sa_family_t family,
			   struct in_addr *addr)
{
	struct mptcp_sock *msk = mptcp_token_get_sock(token);
	int err = 0;

	if (!msk)
		return -EINVAL;

	if (msk->pm.local_valid) {
		err = -EBADR;
		goto announce_put;
	}

	pr_debug("msk=%p, local_id=%d, addr=%x", msk, local_id, addr->s_addr);
	msk->pm.local_valid = 1;
	msk->pm.local_id = local_id;
	msk->pm.local_family = family;
	msk->pm.local_addr.s_addr = addr->s_addr;
	msk->addr_signal = 1;

announce_put:
	sock_put((struct sock *)msk);
	return err;
}

int mptcp_pm_remove_addr(u32 token, u8 local_id)
{
	struct mptcp_sock *msk = mptcp_token_get_sock(token);

	if (!msk)
		return -EINVAL;

	pr_debug("msk=%p", msk);
	msk->pm.local_valid = 0;

	sock_put((struct sock *)msk);
	return 0;
}

int mptcp_pm_create_subflow(u32 token, u8 remote_id, sa_family_t family,
			    struct in_addr *addr)
{
	struct mptcp_sock *msk = mptcp_token_get_sock(token);
	struct sockaddr_in remote;
	struct sockaddr_in local;
	int err;

	if (!msk)
		return -EINVAL;

	pr_debug("msk=%p", msk);

	if (!msk->pm.remote_valid || remote_id != msk->pm.remote_id) {
		err = -EBADR;
		goto create_put;
	}

	local.sin_family = AF_INET;
	local.sin_port = 0;
	if (family == AF_INET)
		local.sin_addr.s_addr = addr->s_addr;
	else
		local.sin_addr.s_addr = htonl(INADDR_ANY);

	remote.sin_family = msk->pm.remote_family;
	remote.sin_port = htons(msk->dport);
	remote.sin_addr.s_addr = msk->pm.remote_addr.s_addr;

	err = mptcp_subflow_connect((struct sock *)msk, &local, &remote,
				    remote_id);

create_put:
	sock_put((struct sock *)msk);
	return err;
}

int mptcp_pm_remove_subflow(u32 token, u8 remote_id)
{
	return -ENOTSUPP;
}

/* path manager event handlers */

void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, token=%u", msk, msk->token);

	pm->server_side = server_side;
	pm->token = msk->token;
}

void mptcp_pm_fully_established(struct mptcp_sock *msk)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	pm->fully_established = 1;
}

void mptcp_pm_connection_closed(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_subflow_established(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_subflow_closed(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_add_addr(struct mptcp_sock *msk, const struct in_addr *addr,
		       u8 id)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, addr=%x, remote_id=%d", msk, addr->s_addr, id);

	pm->remote_addr.s_addr = addr->s_addr;
	pm->remote_id = id;
	pm->remote_family = AF_INET;
	pm->remote_valid = 1;
}

void mptcp_pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr,
			u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_rm_addr(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

/* path manager helpers */

int mptcp_pm_addr_signal(struct mptcp_sock *msk, u8 *id,
			 struct sockaddr_storage *saddr)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)saddr;

	if (!msk->pm.local_valid)
		return -1;

	if (msk->pm.local_family != AF_INET)
		return -1;

	*id = msk->pm.local_id;
	addr->sin_family = msk->pm.local_family;
	addr->sin_addr.s_addr = msk->pm.local_addr.s_addr;

	return 0;
}

int mptcp_pm_get_local_id(struct request_sock *req, struct sock *sk,
			  const struct sk_buff *skb)
{
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (!msk->pm.local_valid)
		return -1;

	/* @@ check if address actually matches... */

	pr_debug("msk=%p, addr_id=%d", msk, msk->pm.local_id);
	subflow_req->local_id = msk->pm.local_id;

	return 0;
}
