// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/inet.h>
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/netns/generic.h>
#include <net/mptcp.h>
#include "protocol.h"

static int pm_pernet_id;

struct pm_pernet {
	struct ctl_table_header *ctl_table_hdr;

	union {
		struct in_addr announce_v4_addr;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr announce_v6_addr;
#endif
	};
	u8	has_announce_v4 : 1,
		has_announce_v6 : 1;
};

struct workqueue_struct *mptcp_wq;
static void announce_addr_worker(struct work_struct *work);
static void create_subflow_worker(struct work_struct *work);

/* path manager command handlers */

int pm_announce_addr(u32 token, sa_family_t family, u8 local_id,
		     struct in_addr *addr)
{
	struct mptcp_sock *msk = mptcp_sk(token_lookup_get(token));
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

int pm_remove_addr(u32 token, u8 local_id)
{
	struct mptcp_sock *msk = mptcp_sk(token_lookup_get(token));

	if (!msk)
		return -EINVAL;

	pr_debug("msk=%p", msk);
	msk->pm.local_valid = 0;

	sock_put((struct sock *)msk);
	return 0;
}

int pm_create_subflow(u32 token, u8 remote_id)
{
	struct mptcp_sock *msk = mptcp_sk(token_lookup_get(token));
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
	local.sin_addr.s_addr = INADDR_ANY;

	remote.sin_family = msk->pm.remote_family;
	remote.sin_port = htons(msk->dport);
	remote.sin_addr.s_addr = msk->pm.remote_addr.s_addr;

	err = subflow_connect((struct sock *)msk, &local, &remote, remote_id);

create_put:
	sock_put((struct sock *)msk);
	return err;
}

int pm_remove_subflow(u32 token, u8 remote_id)
{
	return -ENOTSUPP;
}

/* path manager event handlers */

void pm_new_connection(struct mptcp_sock *msk, int server_side)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, token=%u", msk, msk->token);

	pm->server_side = server_side;
	pm->token = msk->token;

	/* trigger announce address in interim local path manager */
	if (pm->server_side) {
		INIT_WORK(&pm->addr_work, announce_addr_worker);
		queue_work(mptcp_wq, &pm->addr_work);
	}
}

void pm_fully_established(struct mptcp_sock *msk)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	/* trigger create subflow in interim local path manager */
	if (!pm->server_side && !pm->fully_established && pm->remote_valid) {
		INIT_WORK(&pm->subflow_work, create_subflow_worker);
		queue_work(mptcp_wq, &pm->subflow_work);
	}
	pm->fully_established = 1;
}

void pm_connection_closed(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void pm_subflow_established(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_subflow_closed(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_add_addr(struct mptcp_sock *msk, const struct in_addr *addr, u8 id)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, addr=%x, remote_id=%d", msk, addr->s_addr, id);

	msk->pm.remote_addr.s_addr = addr->s_addr;
	msk->pm.remote_id = id;
	msk->pm.remote_family = AF_INET;

	/* trigger create subflow in interim local path manager */
	if (!pm->server_side && !pm->remote_valid && pm->fully_established) {
		INIT_WORK(&pm->subflow_work, create_subflow_worker);
		queue_work(mptcp_wq, &pm->subflow_work);
	}
	pm->remote_valid = 1;
}

void pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_rm_addr(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

/* path manager helpers */

int pm_addr_signal(struct mptcp_sock *msk, u8 *id,
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

int pm_get_local_id(struct request_sock *req, struct sock *sk,
		    const struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (!msk->pm.local_valid)
		return -1;

	/* @@ check if address actually matches... */

	pr_debug("msk=%p, addr_id=%d", msk, msk->pm.local_id);
	subflow_req->local_id = msk->pm.local_id;

	return 0;
}

static int pm_parse_addr(struct pm_pernet *pernet, const char *addr)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (in6_pton(addr, -1, (u8 *)&pernet->announce_v6_addr.s6_addr, '\0',
		     NULL) > 0) {
		pernet->has_announce_v4 = 0;
		pernet->has_announce_v6 = 1;
		return 0;
	}
#endif

	if (in4_pton(addr, -1, (u8 *)&pernet->announce_v4_addr.s_addr, '\0',
		     NULL) > 0) {
		pernet->has_announce_v4 = 1;
		pernet->has_announce_v6 = 0;
		return 0;
	}

	pernet->has_announce_v4 = 0;
	pernet->has_announce_v6 = 0;

	return -1;
}

static int pm_proc_parse_addr(struct ctl_table *ctl, int write,
			      void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	struct pm_pernet *pernet = net_generic(net, pm_pernet_id);
	struct ctl_table tbl;

	char *none = "none";
	char tmp[INET6_ADDRSTRLEN] = { 0 };
	int ret;

	memset(&tbl, 0, sizeof(struct ctl_table));

	if (write) {
		tbl.data = tmp;
		tbl.maxlen = sizeof(tmp);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		if (pernet->has_announce_v6) {
			snprintf(tmp, INET6_ADDRSTRLEN, "%pI6c",
				 &pernet->announce_v6_addr);
			tbl.data = tmp;
		} else
#endif
		if (pernet->has_announce_v4) {
			snprintf(tmp, INET_ADDRSTRLEN, "%pI4",
				 &pernet->announce_v4_addr);
			tbl.data = tmp;
		} else {
			tbl.data = none;
		}
		tbl.maxlen = strlen(tbl.data);
	}

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		/* "none" string: we want to remove it */
		if (strncmp(none, tmp, 5) == 0) {
			pernet->has_announce_v4 = 0;
			pernet->has_announce_v6 = 0;
		} else if (pm_parse_addr(pernet, tmp) < 0) {
			ret = -EINVAL;
		}
	}

	return ret;
}

static struct ctl_table pm_sysctl_table[] = {
	{
		.procname = "announce_addr",
		.maxlen = sizeof(char) * (INET6_ADDRSTRLEN),
		.mode = 0644,
		.proc_handler = pm_proc_parse_addr
	},
	{}
};

static int pm_pernet_create_table(struct net *net, struct pm_pernet *pernet)
{
	struct ctl_table *table;
	struct ctl_table_header *hdr;

	table = pm_sysctl_table;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(pm_sysctl_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;
	}

	hdr = register_net_sysctl(net, "net/mptcp/pm", table);
	if (!hdr)
		goto err_reg;

	pernet->ctl_table_hdr = hdr;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static int __net_init pm_init_net(struct net *net)
{
	struct pm_pernet *pernet = net_generic(net, pm_pernet_id);
	int ret;

	ret = pm_pernet_create_table(net, pernet);
	if (ret < 0)
		return ret;

	return 0;
}

static void __net_exit pm_exit_net(struct net *net)
{
	struct pm_pernet *pernet = net_generic(net, pm_pernet_id);
	struct ctl_table *table = pernet->ctl_table_hdr->ctl_table_arg;

	unregister_net_sysctl_table(pernet->ctl_table_hdr);

	/* Note: the callback will only be called per extra netns */
	kfree(table);
}

static struct pernet_operations pm_pernet_ops = {
	.init = pm_init_net,
	.exit = pm_exit_net,
	.id = &pm_pernet_id,
	.size = sizeof(struct pm_pernet),
};

void pm_init(void)
{
	if (register_pernet_subsys(&pm_pernet_ops) < 0)
		panic("Failed to register MPTCP PM pernet subsystem.\n");

	mptcp_wq = alloc_workqueue("mptcp_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 8);
	if (!mptcp_wq)
		panic("Failed to allocate workqueue");
}

static void announce_addr_worker(struct work_struct *work)
{
	struct mptcp_pm_data *pm = container_of(work, struct mptcp_pm_data,
						addr_work);
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);
	struct pm_pernet *pernet;

	pernet = net_generic(sock_net((struct sock *)msk), pm_pernet_id);

	if (pernet->has_announce_v4)
		pm_announce_addr(pm->token, AF_INET, 1,
				 &pernet->announce_v4_addr);
}

static void create_subflow_worker(struct work_struct *work)
{
	struct mptcp_pm_data *pm = container_of(work, struct mptcp_pm_data,
						subflow_work);

	pm_create_subflow(pm->token, pm->remote_id);
}
