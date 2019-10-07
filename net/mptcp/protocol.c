// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched/signal.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"
#include "mib.h"

static struct percpu_counter mptcp_sockets_allocated;

static void mptcp_set_timeout(const struct sock *sk, const struct sock *ssk)
{
	unsigned long tout = ssk && inet_csk(ssk)->icsk_pending ?
			     inet_csk(ssk)->icsk_timeout - jiffies : 0;

	if (tout <= 0)
		tout = mptcp_sk(sk)->timer_ival;
	mptcp_sk(sk)->timer_ival =  tout > 0 ? tout : TCP_RTO_MIN;
}

bool mptcp_timer_pending(struct sock *sk)
{
	return timer_pending(&inet_csk(sk)->icsk_retransmit_timer);
}

void mptcp_reset_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned long tout;

	/* should never be called with mptcp level timer cleared */
	tout = READ_ONCE(mptcp_sk(sk)->timer_ival);
	if (WARN_ON_ONCE(!tout))
		tout = TCP_RTO_MIN;
	sk_reset_timer(sk, &icsk->icsk_retransmit_timer, jiffies + tout);
}

static void mptcp_stop_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	mptcp_sk(sk)->timer_ival = 0;
}

static struct socket *__mptcp_fallback_get_ref(const struct mptcp_sock *msk)
{
	sock_owned_by_me((const struct sock *)msk);

	if (!msk->subflow)
		return NULL;

	sock_hold(msk->subflow->sk);
	return msk->subflow;
}

static struct socket *mptcp_fallback_get_ref(const struct mptcp_sock *msk)
{
	struct socket *ssock;

	lock_sock((struct sock *)msk);
	ssock = __mptcp_fallback_get_ref(msk);
	release_sock((struct sock *)msk);

	return ssock;
}

static struct sock *mptcp_subflow_get_ref(const struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	sock_owned_by_me((const struct sock *)msk);

	mptcp_for_each_subflow(msk, subflow) {
		struct sock *sk;

		sk = mptcp_subflow_tcp_socket(subflow)->sk;
		sock_hold(sk);
		return sk;
	}

	return NULL;
}

static inline bool mptcp_skb_can_collapse_to(u64 write_seq,
					     const struct sk_buff *skb,
					     const struct mptcp_ext *mpext)
{
	if (!tcp_skb_can_collapse_to(skb))
		return false;

	/* can collapse only if MPTCP level sequence is in order */
	return mpext && mpext->data_seq + mpext->data_len == write_seq;
}

static inline bool mptcp_frag_can_collapse_to(const struct mptcp_sock *msk,
					      const struct page_frag *pfrag,
					      const struct mptcp_data_frag *df)
{
	return df && pfrag->page == df->page &&
		df->data_seq + df->data_len == msk->write_seq;
}

static void dfrag_clear(struct sock *sk, struct mptcp_data_frag *dfrag)
{
	list_del(&dfrag->list);
	sk_mem_uncharge(sk, dfrag->data_len + dfrag->overhead);
	put_page(dfrag->page);
}

static void mptcp_clean_una(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_data_frag *dtmp, *dfrag;
	u64 snd_una = atomic64_read(&msk->snd_una);

	list_for_each_entry_safe(dfrag, dtmp, &msk->rtx_queue, list) {
		if (after64(dfrag->data_seq + dfrag->data_len, snd_una))
			break;

		dfrag_clear(sk, dfrag);
	}
	sk_mem_reclaim_partial(sk);
}

/* ensure we get enough memory for the frag hdr, beyond some minimal amount of
 * data
 */
bool mptcp_page_frag_refill(struct sock *sk, struct page_frag *pfrag)
{
	if (likely(skb_page_frag_refill(32U + sizeof(struct mptcp_data_frag),
					pfrag, sk->sk_allocation)))
		return true;

	sk->sk_prot->enter_memory_pressure(sk);
	sk_stream_moderate_sndbuf(sk);
	return false;
}

static inline struct mptcp_data_frag *
mptcp_carve_data_frag(const struct mptcp_sock *msk, struct page_frag *pfrag,
		      int orig_offset)
{
	int offset = ALIGN(orig_offset, sizeof(long));
	struct mptcp_data_frag *dfrag;

	dfrag = (struct mptcp_data_frag *)(page_to_virt(pfrag->page) + offset);
	dfrag->data_len = 0;
	dfrag->data_seq = msk->write_seq;
	dfrag->overhead = offset - orig_offset + sizeof(struct mptcp_data_frag);
	dfrag->offset = offset + sizeof(struct mptcp_data_frag);
	dfrag->page = pfrag->page;

	return dfrag;
}

static int mptcp_sendmsg_frag(struct sock *sk, struct sock *ssk,
			      struct msghdr *msg, struct mptcp_data_frag *dfrag,
			      long *timeo, int *pmss_now,
			      int *ps_goal)
{
	int mss_now, avail_size, size_goal, offset, ret, frag_truesize = 0;
	bool dfrag_collapsed, collapsed, can_collapse = false;
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_ext *mpext = NULL;
	bool retransmission = !!dfrag;
	struct page_frag *pfrag;
	struct sk_buff *skb;
	struct page *page;
	u64 *write_seq;
	size_t psize;
	int *poffset;

	/* use the mptcp page cache so that we can easily move the data
	 * from one substream to another, but do per subflow memory accounting
	 * Note: pfrag is used only !retransmission, but the compiler if
	 * fooled into a warning if we don't init here
	 */
	pfrag = sk_page_frag(sk);
	if (!retransmission) {
		while (!mptcp_page_frag_refill(ssk, pfrag)) {
			ret = sk_stream_wait_memory(ssk, timeo);
			if (ret)
				return ret;

			/* id sk_stream_wait_memory() sleeps snd_una can change
			 * significantly, refresh the rtx queue
			 */
			mptcp_clean_una(sk);
		}
		write_seq = &msk->write_seq;
		page = pfrag->page;
	} else {
		write_seq = &dfrag->data_seq;
		page = dfrag->page;
	}

	/* compute copy limit */
	mss_now = tcp_send_mss(ssk, &size_goal, msg->msg_flags);
	*pmss_now = mss_now;
	*ps_goal = size_goal;
	avail_size = size_goal;
	skb = tcp_write_queue_tail(ssk);
	if (skb) {
		mpext = skb_ext_find(skb, SKB_EXT_MPTCP);

		/* Limit the write to the size available in the
		 * current skb, if any, so that we create at most a new skb.
		 * Explicitly tells TCP internals to avoid collapsing on later
		 * queue management operation, to avoid breaking the ext <->
		 * SSN association set here
		 */
		can_collapse = (size_goal - skb->len > 0) &&
			      mptcp_skb_can_collapse_to(*write_seq, skb, mpext);
		if (!can_collapse)
			TCP_SKB_CB(skb)->eor = 1;
		else
			avail_size = size_goal - skb->len;
	}

	if (!retransmission) {
		/* reuse tail pfrag, if possible, or carve a new one from the
		 * page allocator
		 */
		dfrag = mptcp_rtx_tail(sk);
		offset = pfrag->offset;
		dfrag_collapsed = mptcp_frag_can_collapse_to(msk, pfrag, dfrag);
		if (!dfrag_collapsed) {
			dfrag = mptcp_carve_data_frag(msk, pfrag, offset);
			offset = dfrag->offset;
			frag_truesize = dfrag->overhead;
		}
		poffset = &pfrag->offset;
		psize = min_t(size_t, pfrag->size - offset, avail_size);

		/* Copy to page */
		pr_debug("left=%zu", msg_data_left(msg));
		psize = copy_page_from_iter(pfrag->page, offset,
					    min_t(size_t, msg_data_left(msg),
						  psize),
					    &msg->msg_iter);
		pr_debug("left=%zu", msg_data_left(msg));
		if (!psize)
			return -EINVAL;

		if (!sk_wmem_schedule(sk, psize + dfrag->overhead))
			return -ENOMEM;
	} else {
		offset = dfrag->offset;
		poffset = &dfrag->offset;
		psize = min_t(size_t, dfrag->data_len, avail_size);
	}

	/* tell the TCP stack to delay the push so that we can safely
	 * access the skb after the sendpages call
	 */
	ret = do_tcp_sendpages(ssk, page, offset, psize,
			       msg->msg_flags | MSG_SENDPAGE_NOTLAST);
	if (ret <= 0)
		return ret;

	frag_truesize += ret;
	if (!retransmission) {
		if (unlikely(ret < psize))
			iov_iter_revert(&msg->msg_iter, psize - ret);

		/* send successful, keep track of sent data for mptcp-level
		 * retransmission
		 */
		dfrag->data_len += ret;
		if (!dfrag_collapsed) {
			get_page(dfrag->page);
			list_add_tail(&dfrag->list, &msk->rtx_queue);
		}

		/* charge data on mptcp rtx queue to the master socket
		 * Note: we charge such data both to sk and ssk
		 */
		sk->sk_forward_alloc -= frag_truesize;
	}

	collapsed = skb == tcp_write_queue_tail(ssk);
	if (collapsed) {
		WARN_ON_ONCE(!can_collapse);
		/* when collapsing mpext always exists */
		mpext->data_len += ret;
		goto out;
	}

	skb = tcp_write_queue_tail(ssk);
	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (mpext) {
		memset(mpext, 0, sizeof(*mpext));
		mpext->data_seq = *write_seq;
		mpext->subflow_seq = mptcp_subflow_ctx(ssk)->rel_write_seq;
		mpext->data_len = ret;
		mpext->use_map = 1;
		mpext->dsn64 = 1;

		pr_debug("data_seq=%llu subflow_seq=%u data_len=%u dsn64=%d",
			 mpext->data_seq, mpext->subflow_seq, mpext->data_len,
			 mpext->dsn64);
	}
	/* TODO: else fallback; allocation can fail, but we can't easily retire
	 * skbs from the write_queue, as we need to roll-back TCP status
	 */

out:
	*poffset += frag_truesize;
	*write_seq += ret;
	mptcp_subflow_ctx(ssk)->rel_write_seq += ret;

	return ret;
}

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	int mss_now = 0, size_goal = 0, ret = 0;
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *ssock;
	size_t copied = 0;
	struct sock *ssk;
	long timeo;

	pr_debug("msk=%p", msk);
	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sk);
		pr_debug("fallback passthrough");
		ret = sock_sendmsg(ssock, msg);
		sock_put(ssock->sk);
		return ret;
	}

	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk) {
		release_sock(sk);
		return -ENOTCONN;
	}

	if (!msg_data_left(msg)) {
		pr_debug("empty send");
		ret = sock_sendmsg(ssk->sk_socket, msg);
		goto put_out;
	}

	pr_debug("conn_list->subflow=%p", ssk);

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL)) {
		ret = -ENOTSUPP;
		goto put_out;
	}

	lock_sock(ssk);
	mptcp_clean_una(sk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	while (msg_data_left(msg)) {
		ret = mptcp_sendmsg_frag(sk, ssk, msg, NULL, &timeo, &mss_now,
					 &size_goal);
		if (ret < 0)
			break;

		copied += ret;
	}

	mptcp_set_timeout(sk, ssk);
	if (copied) {
		ret = copied;
		tcp_push(ssk, msg->msg_flags, mss_now, tcp_sk(ssk)->nonagle,
			 size_goal);

		/* start the timer, if it's not pending */
		if (!mptcp_timer_pending(sk))
			mptcp_reset_timer(sk);
	}

	release_sock(ssk);

put_out:
	release_sock(sk);
	sock_put(ssk);
	return ret;
}

struct mptcp_read_arg {
	struct msghdr *msg;
};

static u64 expand_seq(u64 old_seq, u16 old_data_len, u64 seq)
{
	if ((u32)seq == (u32)old_seq)
		return old_seq;

	/* Assume map covers data not mapped yet. */
	return seq | ((old_seq + old_data_len + 1) & GENMASK_ULL(63, 32));
}

static u64 get_map_offset(struct mptcp_subflow_context *subflow)
{
	return tcp_sk(mptcp_subflow_tcp_socket(subflow)->sk)->copied_seq -
		      subflow->ssn_offset -
		      subflow->map_subflow_seq;
}

static u64 get_mapped_dsn(struct mptcp_subflow_context *subflow)
{
	return subflow->map_seq + get_map_offset(subflow);
}

static int mptcp_read_actor(read_descriptor_t *desc, struct sk_buff *skb,
			    unsigned int offset, size_t len)
{
	struct mptcp_read_arg *arg = desc->arg.data;
	size_t copy_len;

	copy_len = min(desc->count, len);

	if (likely(arg->msg)) {
		int err;

		err = skb_copy_datagram_msg(skb, offset, arg->msg, copy_len);
		if (err) {
			pr_debug("error path");
			desc->error = err;
			return err;
		}
	} else {
		pr_debug("Flushing skb payload");
	}

	// MSG_PEEK support? Other flags? MSG_TRUNC?

	desc->count -= copy_len;

	pr_debug("consumed %zu bytes, %zu left", copy_len, desc->count);
	return copy_len;
}

enum mapping_status {
	MAPPING_ADDED,
	MAPPING_MISSING,
	MAPPING_EMPTY,
	MAPPING_DATA_FIN
};

static enum mapping_status mptcp_get_mapping(struct sock *ssk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(ssk);
	struct mptcp_ext *mpext;
	enum mapping_status ret;
	struct sk_buff *skb;
	u64 map_seq;

	skb = skb_peek(&ssk->sk_receive_queue);
	if (!skb) {
		pr_debug("Empty queue");
		return MAPPING_EMPTY;
	}

	mpext = mptcp_get_ext(skb);

	if (!mpext) {
		/* This is expected for non-DSS data packets */
		return MAPPING_MISSING;
	}

	if (!mpext->use_map) {
		ret = MAPPING_MISSING;
		goto del_out;
	}

	pr_debug("seq=%llu is64=%d ssn=%u data_len=%u", mpext->data_seq,
		 mpext->dsn64, mpext->subflow_seq, mpext->data_len);

	if (mpext->data_len == 0) {
		pr_err("Infinite mapping not handled");
		MPTCP_INC_STATS(sock_net(ssk), MPTCP_MIB_INFINITEMAPRX);
		ret = MAPPING_MISSING;
		goto del_out;
	} else if (mpext->subflow_seq == 0 &&
		   mpext->data_fin == 1) {
		pr_debug("DATA_FIN with no payload");
		ret = MAPPING_DATA_FIN;
		goto del_out;
	}

	if (!mpext->dsn64) {
		map_seq = expand_seq(subflow->map_seq, subflow->map_data_len,
				     mpext->data_seq);
		pr_debug("expanded seq=%llu", subflow->map_seq);
	} else {
		map_seq = mpext->data_seq;
	}

	if (subflow->map_valid) {
		/* due to GSO/TSO we can receive the same mapping multiple
		 * times, before it's expiration.
		 */
		if (subflow->map_seq != map_seq ||
		    subflow->map_subflow_seq != mpext->subflow_seq ||
		    subflow->map_data_len != mpext->data_len) {
			MPTCP_INC_STATS(sock_net(ssk), MPTCP_MIB_DSSNOMATCH);
			pr_warn("Replaced mapping before it was done");
		}
	}

	subflow->map_seq = map_seq;
	subflow->map_subflow_seq = mpext->subflow_seq;
	subflow->map_data_len = mpext->data_len;
	subflow->map_valid = 1;
	ret = MAPPING_ADDED;
	pr_debug("new map seq=%llu subflow_seq=%u data_len=%u",
		 subflow->map_seq, subflow->map_subflow_seq,
		 subflow->map_data_len);

del_out:
	__skb_ext_del(skb, SKB_EXT_MPTCP);
	return ret;
}

static void mptcp_wait_data(struct sock *sk, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	struct mptcp_sock *msk = mptcp_sk(sk);
	int data_ready;

	add_wait_queue(sk_sleep(sk), &wait);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);

	release_sock(sk);

	smp_mb__before_atomic();
	data_ready = test_and_clear_bit(MPTCP_DATA_READY, &msk->flags);
	smp_mb__after_atomic();

	if (!data_ready)
		*timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, *timeo);

	sched_annotate_sleep();
	lock_sock(sk);

	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
}

static void warn_bad_map(struct mptcp_subflow_context *subflow, u32 ssn)
{
	WARN_ONCE(1, "Bad mapping: ssn=%d map_seq=%d map_data_len=%d",
		  ssn, subflow->map_subflow_seq, subflow->map_data_len);
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_subflow_context *subflow;
	struct mptcp_read_arg arg;
	read_descriptor_t desc;
	struct socket *ssock;
	struct tcp_sock *tp;
	struct sock *ssk;
	int copied = 0;
	long timeo;

	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sk);
		pr_debug("fallback-read subflow=%p",
			 mptcp_subflow_ctx(ssock->sk));
		copied = sock_recvmsg(ssock, msg, flags);
		sock_put(ssock->sk);
		return copied;
	}

	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk) {
		release_sock(sk);
		return -ENOTCONN;
	}

	subflow = mptcp_subflow_ctx(ssk);
	tp = tcp_sk(ssk);

	lock_sock(ssk);

	desc.arg.data = &arg;
	desc.error = 0;

	timeo = sock_rcvtimeo(sk, nonblock);

	len = min_t(size_t, len, INT_MAX);

	while (copied < len) {
		enum mapping_status status;
		u32 map_remaining;
		int bytes_read;
		u64 ack_seq;
		u64 old_ack;
		u32 ssn;

		smp_mb__before_atomic();
		clear_bit(MPTCP_DATA_READY, &msk->flags);
		smp_mb__after_atomic();

		status = mptcp_get_mapping(ssk);

		if (status == MAPPING_ADDED) {
			/* Common case, but nothing to do here */
		} else if (status == MAPPING_MISSING) {
			struct sk_buff *skb = skb_peek(&ssk->sk_receive_queue);

			if (!skb->len) {
				/* the TCP stack deliver 0 len FIN pkt
				 * to the receive queue, that is the only
				 * 0len pkts ever expected here, and we can
				 * admit no mapping only for 0 len pkts
				 */
				if (!(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
					WARN_ONCE(1, "0len seq %d:%d flags %x",
						  TCP_SKB_CB(skb)->seq,
						  TCP_SKB_CB(skb)->end_seq,
						  TCP_SKB_CB(skb)->tcp_flags);
				sk_eat_skb(sk, skb);
				continue;
			}
			if (!subflow->map_valid) {
				WARN_ONCE(1, "corrupted stream: missing mapping");
				copied = -EBADFD;
				break;
			}
		} else if (status == MAPPING_EMPTY) {
			goto wait_for_data;
		} else if (status == MAPPING_DATA_FIN) {
			/* TODO: Handle according to RFC 6824 */
			if (!copied) {
				pr_err("Can't read after DATA_FIN");
				copied = -ENOTCONN;
			}

			break;
		}

		ssn = tcp_sk(ssk)->copied_seq - subflow->ssn_offset;
		old_ack = msk->ack_seq;

		if (unlikely(before(ssn, subflow->map_subflow_seq))) {
			/* Mapping covers data later in the subflow stream,
			 * currently unsupported.
			 */
			warn_bad_map(subflow, ssn);
			copied = -EBADFD;
			break;
		} else if (unlikely(!before(ssn, (subflow->map_subflow_seq +
						  subflow->map_data_len)))) {
			/* Mapping ends earlier in the subflow stream.
			 * Invalid
			 */
			warn_bad_map(subflow, ssn);
			copied = -EBADFD;
			break;
		}

		ack_seq = get_mapped_dsn(subflow);
		map_remaining = subflow->map_data_len - get_map_offset(subflow);

		if (before64(ack_seq, old_ack)) {
			/* Mapping covers data already received, discard data
			 * in the current mapping
			 */
			arg.msg = NULL;
			desc.count = min_t(size_t, old_ack - ack_seq,
					   map_remaining);
			pr_debug("Dup data, map len=%d acked=%lld dropped=%ld",
				 map_remaining, old_ack - ack_seq, desc.count);
		} else {
			arg.msg = msg;
			desc.count = min_t(size_t, len - copied, map_remaining);
		}

		/* Read mapped data */
		bytes_read = tcp_read_sock(ssk, &desc, mptcp_read_actor);
		if (bytes_read < 0)
			break;

		/* Refresh current MPTCP sequence number based on subflow seq */
		ack_seq = get_mapped_dsn(subflow);

		if (before64(old_ack, ack_seq))
			msk->ack_seq = ack_seq;

		if (!before(tcp_sk(ssk)->copied_seq - subflow->ssn_offset,
			    subflow->map_subflow_seq + subflow->map_data_len)) {
			subflow->map_valid = 0;
			pr_debug("Done with mapping: seq=%u data_len=%u",
				 subflow->map_subflow_seq,
				 subflow->map_data_len);
		}

		if (arg.msg)
			copied += bytes_read;

		/* The 'wait_for_data' code path can terminate the receive loop
		 * in a number of scenarios: check if more data is pending
		 * before giving up.
		 */
		if (!skb_queue_empty(&ssk->sk_receive_queue))
			continue;

wait_for_data:
		if (copied)
			break;

		if (tp->urg_data && tp->urg_seq == tp->copied_seq) {
			pr_err("Urgent data present, cannot proceed");
			break;
		}

		if (ssk->sk_err || ssk->sk_state == TCP_CLOSE ||
		    (ssk->sk_shutdown & RCV_SHUTDOWN) || !timeo ||
		    signal_pending(current)) {
			pr_debug("nonblock or error");
			break;
		}

		/* Handle blocking and retry read if needed.
		 *
		 * Wait on MPTCP sock, the subflow will notify via data ready.
		 */

		pr_debug("block");
		release_sock(ssk);
		mptcp_wait_data(sk, &timeo);
		lock_sock(ssk);
	}

	release_sock(ssk);
	release_sock(sk);

	sock_put(ssk);

	return copied;
}

static void mptcp_retransmit_handler(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (atomic64_read(&msk->snd_una) == msk->write_seq) {
		mptcp_stop_timer(sk);
	} else {
		if (schedule_work(&msk->rtx_work))
			sock_hold(sk);
	}
}

static void mptcp_retransmit_timer(struct timer_list *t)
{
	struct inet_connection_sock *icsk = from_timer(icsk, t,
						       icsk_retransmit_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		mptcp_retransmit_handler(sk);
	} else {
		/* delegate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_WRITE_TIMER_DEFERRED,
				      &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void mptcp_retransmit(struct work_struct *work)
{
	int orig_len, orig_offset, ret, mss_now = 0, size_goal = 0;
	struct mptcp_data_frag *dfrag;
	struct sock *ssk, *sk;
	struct mptcp_sock *msk;
	u64 orig_write_seq;
	size_t copied = 0;
	struct msghdr msg;
	long timeo = 0;

	msk = container_of(work, struct mptcp_sock, rtx_work);
	sk = &msk->sk.icsk_inet.sk;

	lock_sock(sk);
	mptcp_clean_una(sk);
	dfrag = mptcp_rtx_head(sk);
	if (!dfrag)
		goto unlock;

	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk)
		goto reset_unlock;

	lock_sock(ssk);

	msg.msg_flags = MSG_DONTWAIT;
	orig_len = dfrag->data_len;
	orig_offset = dfrag->offset;
	orig_write_seq = dfrag->data_seq;
	while (dfrag->data_len > 0) {
		ret = mptcp_sendmsg_frag(sk, ssk, &msg, dfrag, &timeo, &mss_now,
					 &size_goal);
		if (ret < 0)
			break;

		MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_RETRANSSEGS);
		copied += ret;
		dfrag->data_len -= ret;
	}
	if (copied)
		tcp_push(ssk, msg.msg_flags, mss_now, tcp_sk(ssk)->nonagle,
			 size_goal);

	dfrag->data_seq = orig_write_seq;
	dfrag->offset = orig_offset;
	dfrag->data_len = orig_len;

	mptcp_set_timeout(sk, ssk);
	release_sock(ssk);
	sock_put(ssk);

reset_unlock:
	if (!mptcp_timer_pending(sk))
		mptcp_reset_timer(sk);

unlock:
	release_sock(sk);
	sock_put(sk);
}

static int __mptcp_init_sock(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	INIT_LIST_HEAD(&msk->conn_list);
	INIT_LIST_HEAD(&msk->rtx_queue);

	INIT_WORK(&msk->rtx_work, mptcp_retransmit);

	/* re-use the csk retrans timer for MPTCP-level retrans */
	timer_setup(&msk->sk.icsk_retransmit_timer, mptcp_retransmit_timer, 0);

	return 0;
}

static int mptcp_init_sock(struct sock *sk)
{
	struct net *net = sock_net(sk);
	int ret;

	if (!mptcp_is_enabled(net))
		return -ENOPROTOOPT;

	if (unlikely(!net->mib.mptcp_statistics) && !mptcp_mib_alloc(net))
		return -ENOMEM;

	ret = __mptcp_init_sock(sk);
	if (ret)
		return ret;

	sk_sockets_allocated_inc(sk);

	return 0;
}

static void __mptcp_clear_xmit(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_data_frag *dtmp, *dfrag;

	sk_stop_timer(sk, &msk->sk.icsk_retransmit_timer);

	list_for_each_entry_safe(dfrag, dtmp, &msk->rtx_queue, list)
		dfrag_clear(sk, dfrag);
}

static void mptcp_cancel_rtx_work(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (cancel_work_sync(&msk->rtx_work))
		sock_put(sk);
}

static void mptcp_close(struct sock *sk, long timeout)
{
	struct mptcp_subflow_context *subflow, *tmp;
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *ssk = NULL;

	mptcp_token_destroy(msk->token);
	inet_sk_state_store(sk, TCP_CLOSE);

	lock_sock(sk);

	if (msk->subflow) {
		ssk = msk->subflow;
		msk->subflow = NULL;
	}

	if (ssk) {
		pr_debug("subflow=%p", ssk->sk);
		sock_release(ssk);
	}

	list_for_each_entry_safe(subflow, tmp, &msk->conn_list, node) {
		pr_debug("conn_list->subflow=%p", subflow);
		sock_release(mptcp_subflow_tcp_socket(subflow));
	}

	__mptcp_clear_xmit(sk);
	release_sock(sk);

	mptcp_cancel_rtx_work(sk);

	sk_common_release(sk);
}

static int mptcp_disconnect(struct sock *sk, int flags)
{
	lock_sock(sk);
	__mptcp_clear_xmit(sk);
	release_sock(sk);
	mptcp_cancel_rtx_work(sk);
	return tcp_disconnect(sk, flags);
}

static struct sock *mptcp_accept(struct sock *sk, int flags, int *err,
				 bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_subflow_context *subflow;
	struct socket *new_sock;
	struct socket *listener;
	struct sock *newsk;

	listener = msk->subflow;

	pr_debug("msk=%p, listener=%p", msk, mptcp_subflow_ctx(listener->sk));
	*err = kernel_accept(listener, &new_sock, flags);
	if (*err < 0)
		return NULL;

	subflow = mptcp_subflow_ctx(new_sock->sk);
	pr_debug("msk=%p, new subflow=%p, ", msk, subflow);

	if (subflow->mp_capable) {
		struct sock *new_mptcp_sock;
		u64 ack_seq;

		lock_sock(sk);

		local_bh_disable();
		new_mptcp_sock = sk_clone_lock(sk, GFP_ATOMIC);
		if (!new_mptcp_sock) {
			*err = -ENOBUFS;
			local_bh_enable();
			release_sock(sk);
			kernel_sock_shutdown(new_sock, SHUT_RDWR);
			sock_release(new_sock);
			return NULL;
		}

		__mptcp_init_sock(new_mptcp_sock);

		msk = mptcp_sk(new_mptcp_sock);
		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;

		mptcp_token_update_accept(new_sock->sk, new_mptcp_sock);
		msk->subflow = NULL;

		mptcp_pm_new_connection(msk, 1);

		mptcp_crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		atomic64_set(&msk->snd_una, msk->write_seq);
		ack_seq++;
		msk->ack_seq = ack_seq;
		subflow->map_seq = ack_seq;
		subflow->map_subflow_seq = 1;
		subflow->rel_write_seq = 1;
		subflow->tcp_sock = new_sock;
		newsk = new_mptcp_sock;
		subflow->conn = new_mptcp_sock;
		list_add(&subflow->node, &msk->conn_list);
		bh_unlock_sock(new_mptcp_sock);

		__MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEPASSIVEACK);
		local_bh_enable();

		inet_sk_state_store(newsk, TCP_ESTABLISHED);
		release_sock(sk);
	} else {
		newsk = new_sock->sk;
		tcp_sk(newsk)->is_mptcp = 0;
		new_sock->sk = NULL;
		sock_release(new_sock);

		MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEPASSIVEFALLBACK);
	}

	return newsk;
}

static void mptcp_destroy(struct sock *sk)
{
	sk_sockets_allocated_dec(sk);
}

static int mptcp_setsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, unsigned int optlen)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	char __kernel *optval;
	struct socket *ssock;
	int ret;

	/* will be treated as __user in tcp_setsockopt */
	optval = (char __kernel __force *)uoptval;

	pr_debug("msk=%p", msk);
	ssock = mptcp_fallback_get_ref(msk);
	if (ssock) {
		pr_debug("subflow=%p", ssock->sk);
		ret = kernel_setsockopt(ssock, level, optname, optval, optlen);
		sock_put(ssock->sk);
		return ret;
	}

	/* @@ the meaning of setsockopt() when the socket is connected and
	 * there are multiple subflows is not defined.
	 */
	return -EOPNOTSUPP;
}

static int mptcp_getsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, int __user *uoption)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	char __kernel *optval;
	int __kernel *option;
	struct socket *ssock;
	int ret;

	/* will be treated as __user in tcp_getsockopt */
	optval = (char __kernel __force *)uoptval;
	option = (int __kernel __force *)uoption;

	pr_debug("msk=%p", msk);
	ssock = mptcp_fallback_get_ref(msk);
	if (ssock) {
		pr_debug("subflow=%p", ssock->sk);
		ret = kernel_getsockopt(ssock, level, optname, optval, option);
		sock_put(ssock->sk);
		return ret;
	}

	/* @@ the meaning of getsockopt() when the socket is connected and
	 * there are multiple subflows is not defined.
	 */
	return -EOPNOTSUPP;
}

#define MPTCP_DEFERRED_ALL TCPF_WRITE_TIMER_DEFERRED

/* this is very alike tcp_release_cb() but we must handle differently a
 * different set of events
 */
static void mptcp_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & MPTCP_DEFERRED_ALL))
			return;
		nflags = flags & ~MPTCP_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	sock_release_ownership(sk);

	if (flags & TCPF_WRITE_TIMER_DEFERRED) {
		mptcp_retransmit_handler(sk);
		__sock_put(sk);
	}
}

static int mptcp_get_port(struct sock *sk, unsigned short snum)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p, subflow=%p", msk,
		 mptcp_subflow_ctx(msk->subflow->sk));

	return inet_csk_get_port(msk->subflow->sk, snum);
}

void mptcp_finish_connect(struct sock *sk, int mp_capable)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_sock *msk = mptcp_sk(sk);

	subflow = mptcp_subflow_ctx(msk->subflow->sk);

	if (mp_capable) {
		u64 ack_seq;

		/* sk (new subflow socket) is already locked, but we need
		 * to lock the parent (mptcp) socket now to add the tcp socket
		 * to the subflow list.
		 *
		 * From lockdep point of view, this creates an ABBA type
		 * deadlock: Normally (sendmsg, recvmsg, ..), we lock the mptcp
		 * socket, then acquire a subflow lock.
		 * Here we do the reverse: "subflow lock, then mptcp lock".
		 *
		 * Its alright to do this here, because this subflow is not yet
		 * on the mptcp sockets subflow list.
		 *
		 * IOW, if another CPU has this mptcp socket locked, it cannot
		 * acquire this particular subflow, because subflow->sk isn't
		 * on msk->conn_list.
		 *
		 * This function can be called either from backlog processing
		 * (BH will be enabled) or from softirq, so we need to use BH
		 * locking scheme.
		 */
		local_bh_disable();
		bh_lock_sock_nested(sk);

		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		pr_debug("msk=%p, token=%u", msk, msk->token);
		msk->dport = ntohs(inet_sk(msk->subflow->sk)->inet_dport);

		mptcp_pm_new_connection(msk, 0);

		mptcp_crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		atomic64_set(&msk->snd_una, msk->write_seq);
		ack_seq++;
		msk->ack_seq = ack_seq;
		subflow->map_seq = ack_seq;
		subflow->map_subflow_seq = 1;
		subflow->rel_write_seq = 1;
		list_add(&subflow->node, &msk->conn_list);
		msk->subflow = NULL;
		bh_unlock_sock(sk);
		local_bh_enable();
	} else {
		MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEACTIVEFALLBACK);
	}
	inet_sk_state_store(sk, TCP_ESTABLISHED);
}

void mptcp_finish_join(struct sock *sk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);

	pr_debug("msk=%p, subflow=%p", msk, subflow);

	local_bh_disable();
	bh_lock_sock_nested(subflow->conn);
	list_add_tail(&subflow->node, &msk->conn_list);
	bh_unlock_sock(subflow->conn);
	local_bh_enable();
	inet_sk_state_store(sk, TCP_ESTABLISHED);
}

bool mptcp_sk_is_subflow(const struct sock *sk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	return subflow->mp_join == 1;
}

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_init_sock,
	.disconnect	= mptcp_disconnect,
	.close		= mptcp_close,
	.accept		= mptcp_accept,
	.setsockopt	= mptcp_setsockopt,
	.getsockopt	= mptcp_getsockopt,
	.shutdown	= tcp_shutdown,
	.destroy	= mptcp_destroy,
	.sendmsg	= mptcp_sendmsg,
	.recvmsg	= mptcp_recvmsg,
	.release_cb	= mptcp_release_cb,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= mptcp_get_port,
	.sockets_allocated	= &mptcp_sockets_allocated,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_wmem),
	.sysctl_mem	= sysctl_tcp_mem,
	.obj_size	= sizeof(struct mptcp_sock),
	.no_autobind	= 1,
};

static struct socket *mptcp_socket_create_get(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	struct sock *sk = (struct sock *)msk;
	struct socket *ssock;
	int err;

	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock)
		goto release;

	err = mptcp_subflow_create_socket(sk, &ssock);
	if (err) {
		ssock = ERR_PTR(err);
		goto release;
	}

	msk->subflow = ssock;
	subflow = mptcp_subflow_ctx(msk->subflow->sk);
	subflow->request_mptcp = 1; /* @@ if MPTCP enabled */
	subflow->request_version = 0; /* currently only v0 supported */

	sock_hold(ssock->sk);

release:
	release_sock(sk);
	return ssock;
}

static int mptcp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err = -ENOTSUPP;

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	ssock = mptcp_socket_create_get(msk);
	if (IS_ERR(ssock))
		return PTR_ERR(ssock);

	err = inet_bind(ssock, uaddr, addr_len);
	sock_put(ssock->sk);
	return err;
}

static int mptcp_stream_connect(struct socket *sock, struct sockaddr *uaddr,
				int addr_len, int flags)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err = -ENOTSUPP;

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	ssock = mptcp_socket_create_get(msk);
	if (IS_ERR(ssock))
		return PTR_ERR(ssock);

	err = inet_stream_connect(ssock, uaddr, addr_len, flags);
	sock_put(ssock->sk);
	return err;
}

static int mptcp_getname(struct socket *sock, struct sockaddr *uaddr,
			 int peer)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	struct sock *ssk;
	int ret;

	if (sock->sk->sk_prot == &tcp_prot) {
		/* we are being invoked from __sys_accept4, after
		 * mptcp_accept() has just accepted a non-mp-capable
		 * flow: sk is a tcp_sk, not an mptcp one.
		 *
		 * Hand the socket over to tcp so all further socket ops
		 * bypass mptcp.
		 */
		sock->ops = &inet_stream_ops;
		return inet_getname(sock, uaddr, peer);
	}

	lock_sock(sock->sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sock->sk);
		pr_debug("subflow=%p", ssock->sk);
		ret = inet_getname(ssock, uaddr, peer);
		sock_put(ssock->sk);
		return ret;
	}

	/* @@ the meaning of getname() for the remote peer when the socket
	 * is connected and there are multiple subflows is not defined.
	 * For now just use the first subflow on the list.
	 */
	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk) {
		release_sock(sock->sk);
		return -ENOTCONN;
	}

	ret = inet_getname(ssk->sk_socket, uaddr, peer);
	release_sock(sock->sk);
	sock_put(ssk);
	return ret;
}

static int mptcp_listen(struct socket *sock, int backlog)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err;

	pr_debug("msk=%p", msk);

	ssock = mptcp_socket_create_get(msk);
	if (IS_ERR(ssock))
		return PTR_ERR(ssock);

	err = inet_listen(ssock, backlog);
	sock_put(ssock->sk);
	return err;
}

static int mptcp_stream_accept(struct socket *sock, struct socket *newsock,
			       int flags, bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err;

	pr_debug("msk=%p", msk);

	ssock = mptcp_fallback_get_ref(msk);
	if (!ssock)
		return -EINVAL;

	err = inet_accept(sock, newsock, flags, kern);
	sock_put(ssock->sk);
	return err;
}

static __poll_t mptcp_poll(struct file *file, struct socket *sock,
			   struct poll_table_struct *wait)
{
	struct mptcp_subflow_context *subflow;
	const struct mptcp_sock *msk;
	struct sock *sk = sock->sk;
	struct socket *ssock;
	__poll_t ret = 0;

	msk = mptcp_sk(sk);
	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sk);
		ret = tcp_poll(file, ssock, wait);
		sock_put(ssock->sk);
		return ret;
	}

	mptcp_for_each_subflow(msk, subflow) {
		struct socket *tcp_sock;

		tcp_sock = mptcp_subflow_tcp_socket(subflow);
		ret |= tcp_poll(file, tcp_sock, wait);
	}
	release_sock(sk);

	return ret;
}

static int mptcp_shutdown(struct socket *sock, int how)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct mptcp_subflow_context *subflow;
	struct socket *ssock;
	int ret = 0;

	pr_debug("sk=%p, how=%d", msk, how);

	lock_sock(sock->sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sock->sk);
		pr_debug("subflow=%p", ssock->sk);
		ret = kernel_sock_shutdown(ssock, how);
		sock_put(ssock->sk);
		return ret;
	}

	mptcp_for_each_subflow(msk, subflow) {
		struct socket *tcp_socket;

		tcp_socket = mptcp_subflow_tcp_socket(subflow);
		pr_debug("conn_list->subflow=%p", subflow);
		ret = kernel_sock_shutdown(tcp_socket, how);
	}
	release_sock(sock->sk);

	return ret;
}

static struct proto_ops mptcp_stream_ops;

static struct inet_protosw mptcp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_MPTCP,
	.prot		= &mptcp_prot,
	.ops		= &mptcp_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};

void mptcp_proto_init(void)
{
	mptcp_prot.h.hashinfo = tcp_prot.h.hashinfo;
	mptcp_stream_ops = inet_stream_ops;
	mptcp_stream_ops.bind = mptcp_bind;
	mptcp_stream_ops.connect = mptcp_stream_connect;
	mptcp_stream_ops.poll = mptcp_poll;
	mptcp_stream_ops.accept = mptcp_stream_accept;
	mptcp_stream_ops.getname = mptcp_getname;
	mptcp_stream_ops.listen = mptcp_listen;
	mptcp_stream_ops.shutdown = mptcp_shutdown;

	if (percpu_counter_init(&mptcp_sockets_allocated, 0, GFP_KERNEL))
		panic("Failed to allocate MPTCP pcpu counter\n");

	mptcp_subflow_init();
	mptcp_basic_init();

	if (proto_register(&mptcp_prot, 1) != 0)
		panic("Failed to register MPTCP proto.\n");

	inet_register_protosw(&mptcp_protosw);
}
