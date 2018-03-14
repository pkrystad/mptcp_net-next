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
#include "mptcp_socket.h"

static int mptcp_sock_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow = msk->subflow;

	pr_debug("subflow=%p", subflow->sk);

	return sock_sendmsg(subflow, msg);
}

static int mptcp_sock_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow = msk->subflow;

	pr_debug("subflow=%p", subflow->sk);

	return sock_recvmsg(subflow, msg, flags);
}

static int mptcp_sock_init(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *sf;
	int err;

	pr_debug("msk=%p", msk);

	err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &sf);
	if (!err) {
		pr_debug("subflow=%p", sf->sk);
		msk->subflow = sf;
	}

	return err;
}

static void mptcp_sock_close(struct sock *sk, long timeout)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		sock_release(msk->subflow);
	}
}

static int mptcp_sock_connect(struct sock *sk, struct sockaddr *saddr, int len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	int err;

	saddr->sa_family = AF_INET;

	pr_debug("msk=%p, subflow=%p", msk, msk->subflow->sk);

	err = kernel_connect(msk->subflow, saddr, len, 0);

	sk->sk_state = TCP_ESTABLISHED;

	return err;
}

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_sock_init,
	.close		= mptcp_sock_close,
	.accept		= inet_csk_accept,
	.connect	= mptcp_sock_connect,
	.shutdown	= tcp_shutdown,
	.sendmsg	= mptcp_sock_sendmsg,
	.recvmsg	= mptcp_sock_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.obj_size	= sizeof(struct mptcp_sock),
	.no_autobind	= 1,
};

static struct inet_protosw mptcp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_MPTCP,
	.prot		= &mptcp_prot,
	.ops		= &inet_stream_ops,
};

int __init mptcp_socket_init(void)
{
	int err;

	err = proto_register(&mptcp_prot, 1);
	if (err)
		return err;

	inet_register_protosw(&mptcp_protosw);

	return 0;
}

void __exit mptcp_socket_exit(void)
{
	inet_unregister_protosw(&mptcp_protosw);
	proto_unregister(&mptcp_prot);
}

module_init(mptcp_socket_init);
module_exit(mptcp_socket_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_INET, IPPROTO_MPTCP);
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, IPPROTO_MPTCP);
