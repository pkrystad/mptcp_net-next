/*
 * Multipath TCP
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "mptcp_socket.h"

static int subflow_v4_init_req(struct request_sock *req,
				const struct sock *sk_listener,
				struct sk_buff *skb,
				bool want_cookie)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct subflow_context *listener = subflow_ctx(sk_listener);
	struct tcp_options_received rx_opt;

	tcp_rsk(req)->is_mptcp = 1;
	pr_debug("subflow_req=%p, listener=%p", subflow_req, listener);

	tcp_request_sock_ipv4_ops.init_req(req, sk_listener, skb, 0);

	rx_opt.mptcp.flags = 0;
	rx_opt.mptcp.mp_capable = 0;
	rx_opt.mptcp.mp_join = 0;
	rx_opt.mptcp.dss = 0;
	mptcp_get_options(skb, &rx_opt);

	if (rx_opt.mptcp.mp_capable && listener->request_mptcp) {
		subflow_req->mp_capable = 1;
		if (rx_opt.mptcp.version >= listener->version)
			subflow_req->version = listener->version;
		else
			subflow_req->version = rx_opt.mptcp.version;
		if ((rx_opt.mptcp.flags & (1 << 7)) ||
		     listener->checksum)
			subflow_req->checksum = 1;
		subflow_req->remote_key = rx_opt.mptcp.sndr_key;
	} else {
		subflow_req->mp_capable = 0;
	}
	return 0;
}

static void subflow_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	inet_sk_rx_dst_set(sk, skb);

	pr_debug("subflow=%p", subflow);

	if (subflow->conn) {
		pr_debug("remote_key=%llu", subflow->remote_key);
		mptcp_finish_connect(subflow->conn, subflow->mp_capable);
		subflow->conn = NULL;
	}
}

static struct request_sock_ops subflow_request_sock_ops;
static struct tcp_request_sock_ops subflow_request_sock_ipv4_ops;

static int subflow_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	pr_debug("subflow=%p", subflow);

	/* Never answer to SYNs sent to broadcast or multicast */
	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	return tcp_conn_request(&subflow_request_sock_ops,
				&subflow_request_sock_ipv4_ops,
				sk, skb);
drop:
	tcp_listendrop(sk);
	return 0;
}

static struct sock *subflow_syn_recv_sock(const struct sock *sk,
					  struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst,
					  struct request_sock *req_unhash,
					  bool *own_req)
{
	struct subflow_context *listener = subflow_ctx(sk);
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct sock *child;

	pr_debug("listener=%p, req=%p, conn=%p", sk, req, listener->conn);

	child = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);

	if (child) {
		struct subflow_context *subflow = subflow_ctx(child);

		pr_debug("child=%p", child);
		if (subflow_req->mp_capable) {
			subflow->mp_capable = 1;
			subflow->fourth_ack = 1;
			subflow->remote_key = subflow_req->remote_key;
			subflow->local_key = subflow_req->local_key;
		} else {
			subflow->mp_capable = 0;
		}
	}

	return child;
}

const struct inet_connection_sock_af_ops subflow_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = subflow_finish_connect,
	.conn_request	   = subflow_conn_request,
	.syn_recv_sock	   = subflow_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
	.mtu_reduced	   = tcp_v4_mtu_reduced,
};

static struct subflow_context *subflow_create_ctx(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct subflow_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	pr_debug("subflow=%p", ctx);

	icsk->icsk_ulp_data = ctx;
	ctx->sk = sk;

	return ctx;
}

static int subflow_init(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct subflow_context *ctx;
	int err = 0;

	ctx = subflow_create_ctx(sk);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	pr_debug("subflow=%p", ctx);

	tsk->is_mptcp = 1;
	icsk->icsk_af_ops = &subflow_specific;
out:
	return err;
}

static void subflow_release(struct sock *sk)
{
	struct subflow_context *ctx = subflow_ctx(sk);

	pr_debug("subflow=%p", ctx);

	kfree(ctx);
}

static struct tcp_ulp_ops subflow_ulp_ops __read_mostly = {
	.name			= "mptcp",
	.owner			= THIS_MODULE,
	.init			= subflow_init,
	.release		= subflow_release,
};

int mptcp_subflow_init(void)
{
	subflow_request_sock_ops = tcp_request_sock_ops;
	subflow_request_sock_ops.obj_size = sizeof(struct subflow_request_sock),

	subflow_request_sock_ipv4_ops = tcp_request_sock_ipv4_ops;
	subflow_request_sock_ipv4_ops.init_req = subflow_v4_init_req;

	return tcp_register_ulp(&subflow_ulp_ops);
}

void mptcp_subflow_exit(void)
{
	tcp_unregister_ulp(&subflow_ulp_ops);
}

MODULE_LICENSE("GPL");
