// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <crypto/algapi.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include <net/ip6_route.h>
#include "protocol.h"
#include "mib.h"

static inline void SUBFLOW_REQ_INC_STATS(struct request_sock *req,
					 enum linux_mptcp_mib_field field)
{
	MPTCP_INC_STATS(sock_net(req_to_sk(req)), field);
}

static int subflow_rebuild_header(struct sock *sk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	int err = 0;

	if (subflow->request_mptcp && !subflow->token) {
		pr_debug("subflow=%p", sk);
		err = mptcp_token_new_connect(sk);
	} else if (subflow->request_join && !subflow->local_nonce) {
		pr_debug("subflow=%p", sk);
		mptcp_token_get_sock(subflow->token);

		do {
			get_random_bytes(&subflow->local_nonce, sizeof(u32));
		} while (!subflow->local_nonce);
	}

	return err;
}

static int subflow_v4_rebuild_header(struct sock *sk)
{
	int err;

	err = subflow_rebuild_header(sk);
	if (err)
		return err;

	return inet_sk_rebuild_header(sk);
}

#if IS_ENABLED(CONFIG_IPV6)
static int subflow_v6_rebuild_header(struct sock *sk)
{
	int err;

	err = subflow_rebuild_header(sk);
	if (err)
		return err;

	return inet6_sk_rebuild_header(sk);
}
#endif

static void subflow_req_destructor(struct request_sock *req)
{
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);

	pr_debug("subflow_req=%p", subflow_req);

	if (subflow_req->mp_capable)
		mptcp_token_destroy_request(subflow_req->token);
	tcp_request_sock_ops.destructor(req);
}

/* validate received token and create truncated hmac and nonce for SYN-ACK */
static bool subflow_token_join_request(struct request_sock *req,
				       const struct sk_buff *skb)
{
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);
	u8 hmac[MPTCPOPT_HMAC_LEN];
	struct mptcp_sock *msk;

	msk = mptcp_token_get_sock(subflow_req->token);
	if (!msk) {
		SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_JOINNOTOKEN);
		return false;
	}

	if (mptcp_pm_get_local_id(req, (struct sock *)msk, skb)) {
		sock_put((struct sock *)msk);
		return false;
	}

	get_random_bytes(&subflow_req->local_nonce, sizeof(u32));

	mptcp_crypto_hmac_sha1(msk->local_key, msk->remote_key,
			       subflow_req->local_nonce,
			       subflow_req->remote_nonce, (u32 *)hmac);

	subflow_req->thmac = get_unaligned_be64(hmac);

	sock_put((struct sock *)msk);
	return true;
}

static void __subflow_init_req(struct request_sock *req,
			     const struct sock *sk_listener,
			     struct sk_buff *skb)
{
	struct mptcp_subflow_context *listener = mptcp_subflow_ctx(sk_listener);
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);
	struct tcp_options_received rx_opt;

	pr_debug("subflow_req=%p, listener=%p", subflow_req, listener);

	mptcp_get_options(skb, &rx_opt);

	subflow_req->mp_capable = 0;
	subflow_req->mp_join = 0;

	if (rx_opt.mptcp.mp_capable) {
		SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_MPCAPABLEPASSIVE);

		if (rx_opt.mptcp.mp_join)
			return;
	} else if (rx_opt.mptcp.mp_join) {
		SUBFLOW_REQ_INC_STATS(req, MPTCP_MIB_JOINSYNRX);
	}

	if (rx_opt.mptcp.mp_capable && listener->request_mptcp) {
		int err;

		err = mptcp_token_new_request(req);
		if (err == 0)
			subflow_req->mp_capable = 1;

		if (rx_opt.mptcp.version >= listener->request_version)
			subflow_req->version = listener->request_version;
		else
			subflow_req->version = rx_opt.mptcp.version;
		subflow_req->remote_key = rx_opt.mptcp.sndr_key;
		subflow_req->ssn_offset = TCP_SKB_CB(skb)->seq;
	} else if (rx_opt.mptcp.mp_join && listener->request_mptcp) {
		subflow_req->mp_join = 1;
		subflow_req->backup = rx_opt.mptcp.backup;
		subflow_req->remote_id = rx_opt.mptcp.join_id;
		subflow_req->token = rx_opt.mptcp.token;
		subflow_req->remote_nonce = rx_opt.mptcp.nonce;
		pr_debug("token=%u, remote_nonce=%u", subflow_req->token,
			 subflow_req->remote_nonce);
		if (!subflow_token_join_request(req, skb)) {
			subflow_req->mp_join = 0;
			// @@ need to trigger RST
		}
	}
}

static void subflow_v4_init_req(struct request_sock *req,
				const struct sock *sk_listener,
				struct sk_buff *skb)
{
	tcp_rsk(req)->is_mptcp = 1;

	tcp_request_sock_ipv4_ops.init_req(req, sk_listener, skb);

	__subflow_init_req(req, sk_listener, skb);
}

#if IS_ENABLED(CONFIG_IPV6)
static void subflow_v6_init_req(struct request_sock *req,
				const struct sock *sk_listener,
				struct sk_buff *skb)
{
	tcp_rsk(req)->is_mptcp = 1;

	tcp_request_sock_ipv6_ops.init_req(req, sk_listener, skb);

	__subflow_init_req(req, sk_listener, skb);
}
#endif

/* validate received truncated hmac and create hmac for third ACK */
static bool subflow_thmac_valid(struct mptcp_subflow_context *subflow)
{
	u8 hmac[MPTCPOPT_HMAC_LEN];
	u64 thmac;

	mptcp_crypto_hmac_sha1(subflow->remote_key, subflow->local_key,
			       subflow->remote_nonce, subflow->local_nonce,
			       (u32 *)hmac);

	thmac = get_unaligned_be64(hmac);
	pr_debug("subflow=%p, token=%u, thmac=%llu, subflow->thmac=%llu\n",
		 subflow, subflow->token,
		 (unsigned long long)thmac,
		 (unsigned long long)subflow->thmac);

	return thmac == subflow->thmac;
}

static void __subflow_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	if (!subflow->conn)
		return;

	if (subflow->mp_capable && !subflow->conn_finished) {
		pr_debug("subflow=%p, remote_key=%llu", mptcp_subflow_ctx(sk),
			 subflow->remote_key);
		mptcp_finish_connect(subflow->conn, subflow->mp_capable);
		subflow->conn_finished = 1;

		if (skb) {
			pr_debug("synack seq=%u", TCP_SKB_CB(skb)->seq);
			subflow->ssn_offset = TCP_SKB_CB(skb)->seq;
		}
	} else if (subflow->mp_join && !subflow->conn_finished) {
		pr_debug("subflow=%p, thmac=%llu, remote_nonce=%u",
			 subflow, subflow->thmac,
			 subflow->remote_nonce);
		if (!subflow_thmac_valid(subflow)) {
			MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_JOINACKMAC);
			subflow->mp_join = 0;
			// @@ need to trigger RST
			return;
		}

		mptcp_crypto_hmac_sha1(subflow->local_key, subflow->remote_key,
				       subflow->local_nonce,
				       subflow->remote_nonce,
				       (u32 *)subflow->hmac);

		mptcp_finish_join(sk);
		subflow->conn_finished = 1;
	}
}

static void subflow_v4_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	inet_sk_rx_dst_set(sk, skb);

	__subflow_finish_connect(sk, skb);
}

#if IS_ENABLED(CONFIG_IPV6)
static void subflow_v6_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	inet6_sk_rx_dst_set(sk, skb);

	__subflow_finish_connect(sk, skb);
}
#endif

static struct request_sock_ops subflow_request_sock_ops;
static struct tcp_request_sock_ops subflow_request_sock_ipv4_ops;
#if IS_ENABLED(CONFIG_IPV6)
static struct tcp_request_sock_ops subflow_request_sock_ipv6_ops;
#endif

static int subflow_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

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

static int subflow_v6_conn_request(struct sock *sk, struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return tcp_v4_conn_request(sk, skb);

	if (!ipv6_unicast_destination(skb))
		goto drop;

	return tcp_conn_request(&subflow_request_sock_ops,
				&subflow_request_sock_ipv6_ops, sk, skb);

drop:
	tcp_listendrop(sk);
	return 0; /* don't send reset */
}

/* validate hmac received in third ACK */
static bool subflow_hmac_valid(const struct request_sock *req,
			       const struct tcp_options_received *rx_opt)
{
	const struct mptcp_subflow_request_sock *subflow_req;
	u8 hmac[MPTCPOPT_HMAC_LEN];
	struct mptcp_sock *msk;
	bool ret;

	subflow_req = mptcp_subflow_rsk(req);
	msk = mptcp_token_get_sock(subflow_req->token);
	if (!msk)
		return false;

	mptcp_crypto_hmac_sha1(msk->remote_key, msk->local_key,
			       subflow_req->remote_nonce,
			       subflow_req->local_nonce, (u32 *)hmac);

	ret = true;
	if (crypto_memneq(hmac, rx_opt->mptcp.hmac, sizeof(hmac)))
		ret = false;

	sock_put((struct sock *)msk);
	return ret;
}

static struct sock *subflow_v4_syn_recv_sock(const struct sock *sk,
					     struct sk_buff *skb,
					     struct request_sock *req,
					     struct dst_entry *dst,
					     struct request_sock *req_unhash,
					     bool *own_req)
{
	struct mptcp_subflow_context *listener = mptcp_subflow_ctx(sk);
	struct mptcp_subflow_request_sock *subflow_req;
	struct tcp_options_received opt_rx;
	struct sock *child;

	pr_debug("listener=%p, req=%p, conn=%p", listener, req, listener->conn);

	/* if the sk is MP_CAPABLE, we already received the client key */
	subflow_req = mptcp_subflow_rsk(req);
	if (!subflow_req->mp_capable && subflow_req->mp_join) {
		opt_rx.mptcp.mp_join = 0;
		mptcp_get_options(skb, &opt_rx);
		if (!opt_rx.mptcp.mp_join ||
		    !subflow_hmac_valid(req, &opt_rx))
			return NULL;
	}

	child = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);

	if (child && *own_req) {
		struct mptcp_subflow_context *ctx = mptcp_subflow_ctx(child);

		if (!ctx)
			goto close_child;

		if (ctx->mp_capable) {
			if (mptcp_token_new_accept(ctx->token))
				goto close_child;
		} else if (ctx->mp_join) {
			struct mptcp_sock *owner;

			owner = mptcp_token_get_sock(ctx->token);
			if (!owner)
				goto close_child;

			ctx->conn = (struct sock *)owner;
			mptcp_finish_join(child);
		}
	}

	return child;

close_child:
	pr_debug("closing child socket");
	inet_sk_set_state(child, TCP_CLOSE);
	sock_set_flag(child, SOCK_DEAD);
	inet_csk_destroy_sock(child);
	return NULL;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sock *subflow_v6_syn_recv_sock(const struct sock *sk,
					     struct sk_buff *skb,
					     struct request_sock *req,
					     struct dst_entry *dst,
					     struct request_sock *req_unhash,
					     bool *own_req)
{
	struct mptcp_subflow_context *listener = mptcp_subflow_ctx(sk);
	struct mptcp_subflow_request_sock *subflow_req;
	struct tcp_options_received opt_rx;
	struct sock *child;

	pr_debug("listener=%p, req=%p, conn=%p", listener, req, listener->conn);

	/* if the sk is MP_CAPABLE, we already received the client key */
	subflow_req = mptcp_subflow_rsk(req);
	if (!subflow_req->mp_capable && subflow_req->mp_join) {
		opt_rx.mptcp.mp_join = 0;
		mptcp_get_options(skb, &opt_rx);
		if (!opt_rx.mptcp.mp_join ||
		    !subflow_hmac_valid(req, &opt_rx))
			return NULL;
	}

	child = tcp_v6_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);

	if (child && *own_req) {
		struct mptcp_subflow_context *ctx = mptcp_subflow_ctx(child);

		if (!ctx)
			goto close_child;

		if (ctx->mp_capable) {
			if (mptcp_token_new_accept(ctx->token))
				goto close_child;
		} else if (ctx->mp_join) {
			struct mptcp_sock *owner;

			owner = mptcp_token_get_sock(ctx->token);
			if (!owner)
				goto close_child;

			ctx->conn = (struct sock *)owner;
			mptcp_finish_join(child);
		}
	}

	return child;

close_child:
	pr_debug("closing child socket");
	inet_sk_set_state(child, TCP_CLOSE);
	sock_set_flag(child, SOCK_DEAD);
	inet_csk_destroy_sock(child);
	return NULL;
}
#endif

static struct inet_connection_sock_af_ops subflow_v4_specific;
#if IS_ENABLED(CONFIG_IPV6)
static struct inet_connection_sock_af_ops subflow_v6_specific;
#endif

static void subflow_data_ready(struct sock *sk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct sock *parent = subflow->conn;

	pr_debug("sk=%p", sk);
	subflow->tcp_sk_data_ready(sk);

	if (parent) {
		pr_debug("parent=%p", parent);

		smp_mb__before_atomic();
		set_bit(MPTCP_DATA_READY, &mptcp_sk(parent)->flags);
		smp_mb__after_atomic();

		parent->sk_data_ready(parent);
	}
}

int mptcp_subflow_connect(struct sock *sk, struct sockaddr_in *local,
			  struct sockaddr_in *remote, u8 remote_id)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_subflow_context *subflow;
	struct socket *sf;
	u32 remote_token;
	int err;

	lock_sock(sk);
	err = mptcp_subflow_create_socket(sk, local->sin_family, &sf);
	if (err) {
		release_sock(sk);
		return err;
	}

	subflow = mptcp_subflow_ctx(sf->sk);
	subflow->remote_key = msk->remote_key;
	subflow->local_key = msk->local_key;
	subflow->token = msk->token;

	sock_hold(sf->sk);
	release_sock(sk);

	err = kernel_bind(sf, (struct sockaddr *)local,
			  sizeof(struct sockaddr_in));
	if (err)
		goto failed;

	mptcp_crypto_key_sha1(subflow->remote_key, &remote_token, NULL);
	pr_debug("msk=%p remote_token=%u", msk, remote_token);
	subflow->remote_token = remote_token;
	subflow->remote_id = remote_id;
	subflow->request_join = 1;
	subflow->request_bkup = 1;

	err = kernel_connect(sf, (struct sockaddr *)remote,
			     sizeof(struct sockaddr_in), O_NONBLOCK);
	if (err && err != -EINPROGRESS)
		goto failed;

	sock_put(sf->sk);
	return err;

failed:
	sock_put(sf->sk);
	sock_release(sf);
	return err;
}

int mptcp_subflow_create_socket(struct sock *sk, sa_family_t family,
				struct socket **new_sock)
{
	struct mptcp_subflow_context *subflow;
	struct net *net = sock_net(sk);
	struct socket *sf;
	int err;

	pr_debug("msk=%p, family=%d", sk, family);

	err = sock_create_kern(net, family, SOCK_STREAM, IPPROTO_TCP, &sf);
	if (err)
		return err;

	lock_sock(sf->sk);
	err = tcp_set_ulp(sf->sk, "mptcp");
	release_sock(sf->sk);

	if (err)
		return err;

	subflow = mptcp_subflow_ctx(sf->sk);
	pr_debug("subflow=%p", subflow);

	*new_sock = sf;
	sock_hold(sk);
	subflow->conn = sk;

	return 0;
}

static struct mptcp_subflow_context *subflow_create_ctx(struct sock *sk,
							struct socket *sock,
							gfp_t priority)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct mptcp_subflow_context *ctx;

	ctx = kzalloc(sizeof(*ctx), priority);
	if (!ctx)
		return NULL;
	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);

	pr_debug("subflow=%p", ctx);

	/* might be NULL */
	ctx->tcp_sock = sock;

	return ctx;
}

static int subflow_ulp_init(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct mptcp_subflow_context *ctx;
	struct tcp_sock *tp = tcp_sk(sk);
	int err = 0;

	if (sk->sk_family == AF_INET) {
		icsk->icsk_af_ops = &subflow_v4_specific;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (sk->sk_family == AF_INET6) {
		icsk->icsk_af_ops = &subflow_v6_specific;
#endif
	} else {
		err = -ENOTSUPP;
		goto out;
	}

	ctx = subflow_create_ctx(sk, sk->sk_socket, GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	pr_debug("subflow=%p, family=%d", ctx, sk->sk_family);

	tp->is_mptcp = 1;
	ctx->tcp_sk_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = subflow_data_ready;
out:
	return err;
}

static void subflow_ulp_release(struct sock *sk)
{
	struct mptcp_subflow_context *ctx = mptcp_subflow_ctx(sk);

	if (!ctx)
		return;

	if (ctx->conn)
		sock_put(ctx->conn);

	kfree_rcu(ctx, rcu);
}

static void subflow_ulp_clone(const struct request_sock *req,
			      struct sock *newsk,
			      const gfp_t priority)
{
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);
	struct mptcp_subflow_context *old_ctx = mptcp_subflow_ctx(newsk);
	struct mptcp_subflow_context *new_ctx;

	/* newsk->sk_socket is NULL at this point */
	new_ctx = subflow_create_ctx(newsk, NULL, priority);
	if (!new_ctx)
		return;

	new_ctx->conn = NULL;
	new_ctx->conn_finished = 1;
	new_ctx->tcp_sk_data_ready = old_ctx->tcp_sk_data_ready;

	if (subflow_req->mp_capable) {
		new_ctx->mp_capable = 1;
		new_ctx->fourth_ack = 1;
		new_ctx->remote_key = subflow_req->remote_key;
		new_ctx->local_key = subflow_req->local_key;
		new_ctx->token = subflow_req->token;
		new_ctx->ssn_offset = subflow_req->ssn_offset;
		new_ctx->idsn = subflow_req->idsn;
	} else if (subflow_req->mp_join) {
		new_ctx->mp_join = 1;
		new_ctx->fourth_ack = 1;
		new_ctx->backup = subflow_req->backup;
		new_ctx->local_id = subflow_req->local_id;
		new_ctx->token = subflow_req->token;
		new_ctx->thmac = subflow_req->thmac;
	}
}

static struct tcp_ulp_ops subflow_ulp_ops __read_mostly = {
	.name		= "mptcp",
	.owner		= THIS_MODULE,
	.init		= subflow_ulp_init,
	.release	= subflow_ulp_release,
	.clone		= subflow_ulp_clone,
};

static int subflow_ops_init(struct request_sock_ops *subflow_ops)
{
	subflow_ops->obj_size = sizeof(struct mptcp_subflow_request_sock);
	subflow_ops->slab_name = "request_sock_subflow";

	subflow_ops->slab = kmem_cache_create(subflow_ops->slab_name,
					      subflow_ops->obj_size, 0,
					      SLAB_ACCOUNT |
					      SLAB_TYPESAFE_BY_RCU,
					      NULL);
	if (!subflow_ops->slab)
		return -ENOMEM;

	subflow_ops->destructor = subflow_req_destructor;

	return 0;
}

void mptcp_subflow_init(void)
{
	subflow_request_sock_ops = tcp_request_sock_ops;
	if (subflow_ops_init(&subflow_request_sock_ops) != 0)
		panic("MPTCP: failed to init subflow request sock ops\n");

	subflow_request_sock_ipv4_ops = tcp_request_sock_ipv4_ops;
	subflow_request_sock_ipv4_ops.init_req = subflow_v4_init_req;

	subflow_v4_specific = ipv4_specific;
	subflow_v4_specific.conn_request = subflow_v4_conn_request;
	subflow_v4_specific.syn_recv_sock = subflow_v4_syn_recv_sock;
	subflow_v4_specific.sk_rx_dst_set = subflow_v4_finish_connect;
	subflow_v4_specific.rebuild_header = subflow_v4_rebuild_header;

#if IS_ENABLED(CONFIG_IPV6)
	subflow_request_sock_ipv6_ops = tcp_request_sock_ipv6_ops;
	subflow_request_sock_ipv6_ops.init_req = subflow_v6_init_req;

	subflow_v6_specific = ipv6_specific;
	subflow_v6_specific.conn_request = subflow_v6_conn_request;
	subflow_v6_specific.syn_recv_sock = subflow_v6_syn_recv_sock;
	subflow_v6_specific.sk_rx_dst_set = subflow_v6_finish_connect;
	subflow_v6_specific.rebuild_header = subflow_v6_rebuild_header;
#endif

	mptcp_diag_subflow_init(&subflow_ulp_ops);

	if (tcp_register_ulp(&subflow_ulp_ops) != 0)
		panic("MPTCP: failed to register subflows to ULP\n");
}
