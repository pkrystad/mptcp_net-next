// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

static struct workqueue_struct *pm_wq;

/* path manager command handlers */

int mptcp_pm_announce_addr(struct mptcp_sock *msk,
			   const struct mptcp_addr_info *addr)
{
	pr_debug("msk=%p, local_id=%d", msk, addr->id);

	msk->pm.local = *addr;
	WRITE_ONCE(msk->pm.addr_signal, true);
	return 0;
}

int mptcp_pm_remove_addr(struct mptcp_sock *msk, u8 local_id)
{
	return -ENOTSUPP;
}

int mptcp_pm_remove_subflow(struct mptcp_sock *msk, u8 remote_id)
{
	return -ENOTSUPP;
}

/* path manager event handlers */

void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, token=%u side=%d", msk, msk->token, server_side);

	WRITE_ONCE(pm->server_side, server_side);
}

static bool mptcp_pm_schedule_work(struct mptcp_sock *msk,
				   enum mptcp_pm_status new_status)
{
	if (msk->pm.status != MPTCP_PM_IDLE)
		return false;

	if (queue_work(pm_wq, &msk->pm.work)) {
		msk->pm.status = new_status;
		sock_hold((struct sock *)msk);
		return true;
	}
	return false;
}

void mptcp_pm_fully_established(struct mptcp_sock *msk)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	/* try to avoid acquiring the lock below */
	if (READ_ONCE(pm->fully_established))
		return;

	spin_lock_bh(&pm->lock);
	if (!READ_ONCE(pm->fully_established) &&
	    mptcp_pm_schedule_work(msk, MPTCP_PM_ESTABLISHED))
		WRITE_ONCE(pm->fully_established, true);

	spin_unlock_bh(&pm->lock);
}

void mptcp_pm_connection_closed(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_subflow_established(struct mptcp_sock *msk,
				  struct mptcp_subflow_context *subflow)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	if (!READ_ONCE(pm->work_pending))
		return;

	spin_lock_bh(&pm->lock);

	if (READ_ONCE(pm->work_pending))
		mptcp_pm_schedule_work(msk, MPTCP_PM_SUBFLOW_ESTABLISHED);

	spin_unlock_bh(&pm->lock);
}

void mptcp_pm_subflow_closed(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_add_addr_received(struct mptcp_sock *msk,
				const struct mptcp_addr_info *addr)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p remote_id=%d accept=%d", msk, addr->id,
		 READ_ONCE(pm->accept_addr));

	/* avoid acquiring the lock if there is no room for fouther addresses */
	if (!READ_ONCE(pm->accept_addr))
		return;

	spin_lock_bh(&pm->lock);

	/* be sure there is something to signal re-checking under PM lock */
	if (READ_ONCE(pm->accept_addr) &&
	    mptcp_pm_schedule_work(msk, MPTCP_PM_ADD_ADDR_RECEIVED))
		pm->remote = *addr;

	spin_unlock_bh(&pm->lock);
}

/* path manager helpers */

bool mptcp_pm_addr_signal(struct mptcp_sock *msk, unsigned int remaining,
			  struct mptcp_addr_info *saddr)
{
	int ret = false;

	spin_lock_bh(&msk->pm.lock);

	/* double check after the lock is acquired */
	if (!mptcp_pm_should_signal(msk))
		goto out_unlock;

	if (remaining < mptcp_add_addr_len(msk->pm.local.family))
		goto out_unlock;

	*saddr = msk->pm.local;
	WRITE_ONCE(msk->pm.addr_signal, false);
	ret = true;

out_unlock:
	spin_unlock_bh(&msk->pm.lock);
	return ret;
}

int mptcp_pm_get_local_id(struct mptcp_sock *msk, struct sock_common *skc)
{
	return mptcp_pm_nl_get_local_id(msk, skc);
}

static void pm_worker(struct work_struct *work)
{
	struct mptcp_pm_data *pm = container_of(work, struct mptcp_pm_data,
						work);
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);
	struct sock *sk = (struct sock *)msk;

	switch (READ_ONCE(pm->status)) {
	case MPTCP_PM_ADD_ADDR_RECEIVED:
		mptcp_pm_nl_add_addr_received(msk);
		break;

	case MPTCP_PM_ESTABLISHED:
		mptcp_pm_nl_fully_established(msk);
		break;

	case MPTCP_PM_SUBFLOW_ESTABLISHED:
		mptcp_pm_nl_subflow_established(msk);
		break;

	default:
		break;
	}

	sock_put(sk);
}

void mptcp_pm_data_init(struct mptcp_sock *msk)
{
	msk->pm.add_addr_signaled = 0;
	msk->pm.add_addr_accepted = 0;
	msk->pm.local_addr_used = 0;
	WRITE_ONCE(msk->pm.work_pending, false);
	WRITE_ONCE(msk->pm.addr_signal, false);
	WRITE_ONCE(msk->pm.fully_established, false);
	WRITE_ONCE(msk->pm.accept_addr, false);
	msk->pm.status = MPTCP_PM_IDLE;

	spin_lock_init(&msk->pm.lock);
	INIT_WORK(&msk->pm.work, pm_worker);

	mptcp_pm_nl_data_init(msk);
}

void mptcp_pm_init(void)
{
	pm_wq = alloc_workqueue("pm_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 8);
	if (!pm_wq)
		panic("Failed to allocate workqueue");

	mptcp_pm_nl_init();
}
