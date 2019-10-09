/* SPDX-License-Identifier: GPL-2.0 */
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __MPTCP_PROTOCOL_H
#define __MPTCP_PROTOCOL_H

#include <linux/random.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

/* MPTCP option bits */
#define OPTION_MPTCP_MPC_SYN	BIT(0)
#define OPTION_MPTCP_MPC_SYNACK	BIT(1)
#define OPTION_MPTCP_MPC_ACK	BIT(2)
#define OPTION_MPTCP_MPJ_SYN	BIT(3)
#define OPTION_MPTCP_MPJ_SYNACK	BIT(4)
#define OPTION_MPTCP_MPJ_ACK	BIT(5)
#define OPTION_MPTCP_ADD_ADDR	BIT(6)
#define OPTION_MPTCP_ADD_ADDR6	BIT(7)
#define OPTION_MPTCP_RM_ADDR	BIT(8)

/* MPTCP option subtypes */
#define MPTCPOPT_MP_CAPABLE	0
#define MPTCPOPT_MP_JOIN	1
#define MPTCPOPT_DSS		2
#define MPTCPOPT_ADD_ADDR	3
#define MPTCPOPT_RM_ADDR	4
#define MPTCPOPT_MP_PRIO	5
#define MPTCPOPT_MP_FAIL	6
#define MPTCPOPT_MP_FASTCLOSE	7

/* MPTCP suboption lengths */
#define TCPOLEN_MPTCP_MPC_SYN		12
#define TCPOLEN_MPTCP_MPC_SYNACK	20
#define TCPOLEN_MPTCP_MPC_ACK		20
#define TCPOLEN_MPTCP_MPJ_SYN		12
#define TCPOLEN_MPTCP_MPJ_SYNACK	16
#define TCPOLEN_MPTCP_MPJ_ACK		24
#define TCPOLEN_MPTCP_DSS_BASE		4
#define TCPOLEN_MPTCP_DSS_ACK32		4
#define TCPOLEN_MPTCP_DSS_ACK64		8
#define TCPOLEN_MPTCP_DSS_MAP32		10
#define TCPOLEN_MPTCP_DSS_MAP64		14
#define TCPOLEN_MPTCP_DSS_CHECKSUM	2
#define TCPOLEN_MPTCP_ADD_ADDR		8
#define TCPOLEN_MPTCP_ADD_ADDR6		20
#define TCPOLEN_MPTCP_RM_ADDR		4

/* MPTCP MP_JOIN flags */
#define MPTCPOPT_BACKUP		BIT(0)
#define MPTCPOPT_HMAC_LEN	20
#define MPTCPOPT_THMAC_LEN	8

/* MPTCP MP_CAPABLE flags */
#define MPTCP_VERSION_MASK	(0x0F)
#define MPTCP_CAP_CHECKSUM_REQD	BIT(7)
#define MPTCP_CAP_EXTENSIBILITY	BIT(6)
#define MPTCP_CAP_HMAC_SHA1	BIT(0)
#define MPTCP_CAP_FLAG_MASK	(0x3F)

/* MPTCP DSS flags */
#define MPTCP_DSS_DATA_FIN	BIT(4)
#define MPTCP_DSS_DSN64		BIT(3)
#define MPTCP_DSS_HAS_MAP	BIT(2)
#define MPTCP_DSS_ACK64		BIT(1)
#define MPTCP_DSS_HAS_ACK	BIT(0)
#define MPTCP_DSS_FLAG_MASK	(0x1F)

/* MPTCP ADD_ADDR flags */
#define MPTCP_ADDR_FAMILY_MASK	(0x0F)
#define MPTCP_ADDR_IPVERSION_4	4
#define MPTCP_ADDR_IPVERSION_6	6

/* MPTCP socket flags */
#define MPTCP_DATA_READY	BIT(0)

static inline __be32 mptcp_option(u8 subopt, u8 len, u8 nib, u8 field)
{
	return htonl((TCPOPT_MPTCP << 24) | (len << 16) | (subopt << 12) |
		     ((nib & 0xF) << 8) | field);
}

struct mptcp_pm_data {
	u8	local_valid;
	u8	local_id;
	sa_family_t local_family;
	union {
		struct in_addr local_addr;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr local_addr6;
#endif
	};
	u8	remote_valid;
	u8	remote_id;
	sa_family_t remote_family;
	union {
		struct in_addr remote_addr;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr remote_addr6;
#endif
	};
	u8	server_side : 1,
		fully_established : 1;

	/* for interim path manager */
	struct	work_struct addr_work;
	struct	work_struct subflow_work;
	u32	token;
};

struct mptcp_data_frag {
	struct list_head list;
	u64 data_seq;
	int data_len;
	int offset;
	int overhead;
	struct page *page;
};

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct inet_connection_sock sk;
	u64		local_key;
	u64		remote_key;
	u64		write_seq;
	u64		ack_seq;
	atomic64_t	snd_una;
	unsigned long	timer_ival;
	u32		token;
	unsigned long	flags;
	u16		dport;
	struct work_struct rtx_work;
	struct list_head conn_list;
	struct list_head rtx_queue;
	struct socket	*subflow; /* outgoing connect/listener/!mp_capable */
	struct mptcp_pm_data	pm;
	u8		addr_signal;
};

#define mptcp_for_each_subflow(__msk, __subflow)			\
	list_for_each_entry(__subflow, &((__msk)->conn_list), node)

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

static inline struct mptcp_data_frag *mptcp_rtx_tail(const struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (list_empty(&msk->rtx_queue))
		return NULL;

	return list_last_entry(&msk->rtx_queue, struct mptcp_data_frag, list);
}

static inline struct mptcp_data_frag *mptcp_rtx_head(const struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (list_empty(&msk->rtx_queue))
		return NULL;

	return list_first_entry(&msk->rtx_queue, struct mptcp_data_frag, list);
}

struct mptcp_subflow_request_sock {
	struct	tcp_request_sock sk;
	u8	mp_capable : 1,
		mp_join : 1,
		backup : 1,
		version : 4;
	u8	local_id;
	u8	remote_id;
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u32	token;
	u32	ssn_offset;
	u64	thmac;
	u32	local_nonce;
	u32	remote_nonce;
};

static inline struct mptcp_subflow_request_sock *
mptcp_subflow_rsk(const struct request_sock *rsk)
{
	return (struct mptcp_subflow_request_sock *)rsk;
}

/* MPTCP subflow context */
struct mptcp_subflow_context {
	struct	list_head node;/* conn_list of subflows */
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u64	map_seq;
	u32	token;
	u32     rel_write_seq;
	u32	map_subflow_seq;
	u32	ssn_offset;
	u16	map_data_len;
	u16	request_mptcp : 1,  /* send MP_CAPABLE */
		request_join : 1,   /* send MP_JOIN */
		request_bkup : 1,
		request_version : 4,
		mp_capable : 1,     /* remote is MPTCP capable */
		mp_join : 1,        /* remote is JOINing */
		fourth_ack : 1,     /* send initial DSS */
		conn_finished : 1,
		map_valid : 1,
		backup : 1;
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u32	remote_token;
	u8	hmac[MPTCPOPT_HMAC_LEN];
	u8	local_id;
	u8	remote_id;

	struct  socket *tcp_sock;  /* underlying tcp_sock */
	struct  sock *conn;        /* parent mptcp_sock */

	void	(*tcp_sk_data_ready)(struct sock *sk);
	struct	rcu_head rcu;
};

static inline struct mptcp_subflow_context *
mptcp_subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* Use RCU on icsk_ulp_data only for sock diag code */
	return (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
}

static inline struct socket *
mptcp_subflow_tcp_socket(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

int mptcp_is_enabled(struct net *net);

void mptcp_subflow_init(void);
int mptcp_subflow_connect(struct sock *sk, struct sockaddr_in *local,
			  struct sockaddr_in *remote, u8 remote_id);
int mptcp_subflow_create_socket(struct sock *sk, sa_family_t family,
				struct socket **new_sock);

extern const struct inet_connection_sock_af_ops ipv4_specific;
void mptcp_proto_init(void);
#if IS_ENABLED(CONFIG_IPV6)
extern const struct inet_connection_sock_af_ops ipv6_specific;
#endif

void mptcp_proto_init(void);
#if IS_ENABLED(CONFIG_IPV6)
int mptcp_proto_v6_init(void);
#endif

void mptcp_get_options(const struct sk_buff *skb,
		       struct tcp_options_received *opt_rx);

void mptcp_finish_connect(struct sock *sk, int mp_capable);
void mptcp_finish_join(struct sock *sk);
void mptcp_reset_timer(struct sock *sk);

int mptcp_token_new_request(struct request_sock *req);
void mptcp_token_destroy_request(u32 token);
int mptcp_token_new_connect(struct sock *sk);
int mptcp_token_new_accept(u32 token);
void mptcp_token_update_accept(struct sock *sk, struct sock *conn);
struct mptcp_sock *mptcp_token_get_sock(u32 token);
void mptcp_token_destroy(u32 token);

void mptcp_crypto_key_sha1(u64 key, u32 *token, u64 *idsn);
static inline void mptcp_crypto_key_gen_sha1(u64 *key, u32 *token, u64 *idsn)
{
	/* we might consider a faster version that computes the key as a
	 * hash of some information available in the MPTCP socket. Use
	 * random data at the moment, as it's probably the safest option
	 * in case multiple sockets are opened in different namespaces at
	 * the same time.
	 */
	get_random_bytes(key, sizeof(u64));
	mptcp_crypto_key_sha1(*key, token, idsn);
}

void mptcp_crypto_hmac_sha1(u64 key1, u64 key2, u32 nonce1, u32 nonce2,
			    u32 *hash_out);

void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side);
void mptcp_pm_fully_established(struct mptcp_sock *msk);
void mptcp_pm_connection_closed(struct mptcp_sock *msk);
void mptcp_pm_subflow_established(struct mptcp_sock *msk, u8 id);
void mptcp_pm_subflow_closed(struct mptcp_sock *msk, u8 id);
void mptcp_pm_add_addr(struct mptcp_sock *msk, const struct in_addr *addr,
		       u8 id);
void mptcp_pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr,
			u8 id);
void mptcp_pm_rm_addr(struct mptcp_sock *msk, u8 id);

int mptcp_pm_announce_addr(u32 token, u8 local_id, sa_family_t family,
			   struct in_addr *addr);
int mptcp_pm_create_subflow(u32 token, u8 remote_id, sa_family_t family,
			    struct in_addr *addr);
int mptcp_pm_remove_addr(u32 token, u8 local_id);
int mptcp_pm_remove_subflow(u32 token, u8 remote_id);

int mptcp_pm_addr_signal(struct mptcp_sock *msk, u8 *id,
			 struct sockaddr_storage *saddr);
int mptcp_pm_get_local_id(struct request_sock *req, struct sock *sk,
			  const struct sk_buff *skb);

void mptcp_basic_init(void);
void mptcp_basic_new_connection(struct mptcp_pm_data *pm);
void mptcp_basic_fully_established(struct mptcp_pm_data *pm);
void mptcp_basic_add_addr(struct mptcp_pm_data *pm);

static inline struct mptcp_ext *mptcp_get_ext(struct sk_buff *skb)
{
	return (struct mptcp_ext *)skb_ext_find(skb, SKB_EXT_MPTCP);
}

static inline bool before64(__u64 seq1, __u64 seq2)
{
	return (__s64)(seq1 - seq2) < 0;
}

#define after64(seq2, seq1)	before64(seq1, seq2)

void mptcp_diag_subflow_init(struct tcp_ulp_ops *ops);

#endif /* __MPTCP_PROTOCOL_H */
