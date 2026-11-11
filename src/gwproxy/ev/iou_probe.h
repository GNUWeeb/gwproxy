// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * What the io_uring loop needs from the kernel, and the startup check for it.
 *
 * The loop queues every close with IOSQE_CQE_SKIP_SUCCESS (Linux 5.17) and
 * ends a pair's requests with IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ALL
 * (Linux 5.19). An older kernel fails such a request with -EINVAL before it
 * runs: the close never happens and the cancel cancels nothing, so sockets and
 * pairs would leak with every connection. Hence the check, run on each
 * worker's ring before it serves anything.
 *
 * The ring's features say whether IOSQE_CQE_SKIP_SUCCESS is known
 * (IORING_FEAT_CQE_SKIP came with it). The cancel flags have no feature bit,
 * so a cancel using them is tried on a descriptor nothing waits on: a kernel
 * that knows them finds nothing to cancel (a count of 0, or -ENOENT), an
 * older one refuses the flags (-EINVAL).
 */
#ifndef GWPROXY__EV__IOU_PROBE_H
#define GWPROXY__EV__IOU_PROBE_H

#include <errno.h>
#include <stddef.h>
#include <liburing.h>

/* The oldest kernel the io_uring loop runs on, for messages. */
#define GWP_IOU_MIN_KERNEL "5.19"

/* user_data of the probe's cancel; the ring is not in use yet. */
#define GWP_IOU_PROBE_TAG 0x70726f6265ull

/*
 * Judge the probe's results: @features, the ring's features, and @cancel_res,
 * the result of the probe's cancel (see gwp_iou_probe_cancel()). Returns NULL
 * when the kernel has all the loop needs, else what it lacks, for a message.
 */
static inline const char *gwp_iou_kernel_lacks(unsigned int features,
					       int cancel_res)
{
	if (!(features & IORING_FEAT_CQE_SKIP))
		return "IOSQE_CQE_SKIP_SUCCESS (Linux 5.17)";

	/*
	 * A cancel with IORING_ASYNC_CANCEL_ALL answers with the number of
	 * requests it cancelled: 0 here, as nothing waits on the probed
	 * descriptor; -ENOENT, the answer of a cancel that found nothing
	 * without that flag, is taken as success too. Anything else,
	 * -EINVAL from a kernel before 5.19 in particular, means the flags
	 * are refused.
	 */
	if (cancel_res < 0 && cancel_res != -ENOENT)
		return "IORING_ASYNC_CANCEL_FD and IORING_ASYNC_CANCEL_ALL (Linux 5.19)";

	return NULL;
}

/*
 * Submit a cancel of every request on @fd with IORING_ASYNC_CANCEL_FD |
 * IORING_ASYNC_CANCEL_ALL on @ring, which must have nothing else in flight,
 * and wait for its completion. Returns the cancel's result, for
 * gwp_iou_kernel_lacks(), in *@res and 0, or a negative errno when the probe
 * itself could not run.
 */
static inline int gwp_iou_probe_cancel(struct io_uring *ring, int fd, int *res)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *s;
	int r;

	s = io_uring_get_sqe(ring);
	if (!s)
		return -EAGAIN;
	io_uring_prep_cancel_fd(s, fd, IORING_ASYNC_CANCEL_ALL);
	s->user_data = GWP_IOU_PROBE_TAG;

	/*
	 * One system call: the cancel completes inline, whether it is
	 * refused or finds nothing, so the wait cannot block.
	 */
	do {
		r = io_uring_submit_and_wait(ring, 1);
	} while (r == -EINTR);
	if (r < 0)
		return r;

	r = io_uring_peek_cqe(ring, &cqe);
	if (r < 0)
		return r;
	if (cqe->user_data != GWP_IOU_PROBE_TAG) {
		io_uring_cqe_seen(ring, cqe);
		return -EPROTO;
	}

	*res = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return 0;
}

#endif /* #ifndef GWPROXY__EV__IOU_PROBE_H */
