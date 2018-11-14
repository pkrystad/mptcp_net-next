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

#ifndef __NET_MPTCP_SOCKET_H
#define __NET_MPTCP_SOCKET_H

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct	inet_connection_sock sk;
	struct	socket *subflow; /* outgoing connect, listener or !mp_capable */

};

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

/* MPTCP subflow context */
struct subflow_context {
	bool	request_mptcp;  // send MP_CAPABLE
	bool	checksum;
	bool	version;
	struct	sock *sk;       // underlying tcp_sock
	struct	sock *conn;     // parent mptcp_sock
};

static inline struct subflow_context *subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	return (struct subflow_context *) icsk->icsk_ulp_data;
}

static inline struct sock *sock_sk(const struct subflow_context *subflow)
{
	return subflow->sk;
}

int mptcp_subflow_init(void);
void mptcp_subflow_exit(void);

#endif /* __NET_MPTCP_SOCKET_H */
