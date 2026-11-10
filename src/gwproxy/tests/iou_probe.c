// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the io_uring loop's kernel check (ev/iou_probe.h): how the
 * probe's results are judged, for kernels older and newer than the loop
 * needs, and the probe itself on this host's kernel.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/ev/iou_probe.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

static unsigned nr_checks;

static void check(unsigned int features, int res, const char *want, int line)
{
	const char *got = gwp_iou_kernel_lacks(features, res);

	if ((!got) != (!want) || (got && !strstr(got, want))) {
		fprintf(stderr, "line %d: features=%#x res=%d: got '%s', want '%s'\n",
			line, features, res, got ? got : "(none)",
			want ? want : "(none)");
		assert(0);
	}
	nr_checks++;
}

#define CHECK(f, res, want) check((f), (res), (want), __LINE__)

#define SKIP	"IOSQE_CQE_SKIP_SUCCESS"
#define CANCEL	"IORING_ASYNC_CANCEL_FD"

/* What the ring features of a few kernels look like, give or take. */
#define FEAT_5_15	(IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP | \
			 IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS | \
			 IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL | \
			 IORING_FEAT_POLL_32BITS | IORING_FEAT_SQPOLL_NONFIXED | \
			 IORING_FEAT_EXT_ARG | IORING_FEAT_NATIVE_WORKERS | \
			 IORING_FEAT_RSRC_TAGS)
#define FEAT_5_17	(FEAT_5_15 | IORING_FEAT_CQE_SKIP)
#define FEAT_5_19	(FEAT_5_17 | IORING_FEAT_LINKED_FILE)

static void test_judge(void)
{
	/* Before 5.17: no IOSQE_CQE_SKIP_SUCCESS, whatever the cancel did. */
	CHECK(0, 0, SKIP);
	CHECK(FEAT_5_15, -EINVAL, SKIP);
	CHECK(FEAT_5_15, -ENOENT, SKIP);
	CHECK(FEAT_5_17 & ~IORING_FEAT_CQE_SKIP, -ENOENT, SKIP);

	/* 5.17 and 5.18 refuse the cancel flags. */
	CHECK(FEAT_5_17, -EINVAL, CANCEL);
	/* Any other failure is no proof that the flags work either. */
	CHECK(FEAT_5_17, -EOPNOTSUPP, CANCEL);
	CHECK(FEAT_5_19, -EBADF, CANCEL);
	CHECK(FEAT_5_19, -EINVAL, CANCEL);

	/* 5.19 and later: nothing to cancel, or (oddly) something. */
	CHECK(FEAT_5_19, 0, NULL);
	CHECK(FEAT_5_17, 0, NULL);
	CHECK(FEAT_5_19, -ENOENT, NULL);
	CHECK(FEAT_5_19, 1, NULL);
	CHECK(~0u, -ENOENT, NULL);
}

/*
 * The probe on this host's ring. Where io_uring_setup() is refused (a
 * container's seccomp profile) there is no ring to probe: say so and pass.
 */
static void test_probe_here(void)
{
	struct io_uring ring;
	int r, res = 1, efd;
	const char *lacks;

	r = io_uring_queue_init(8, &ring, 0);
	if (r < 0) {
		printf("io_uring_queue_init(): %s; probe not run here\n",
		       strerror(-r));
		return;
	}

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	assert(efd >= 0);

	lacks = gwp_iou_kernel_lacks(ring.features, 0);
	if (lacks) {
		printf("this kernel lacks %s; cancel probe not run\n", lacks);
		goto out;
	}

	r = gwp_iou_probe_cancel(&ring, efd, &res);
	assert(r == 0);
	lacks = gwp_iou_kernel_lacks(ring.features, res);
	printf("probe: features=%#x cancel=%d: %s\n", ring.features, res,
	       lacks ? lacks : "supported");
	if (!lacks)
		assert(res == 0 || res == -ENOENT);

	/* The probe leaves nothing behind: a second one gives the same. */
	r = gwp_iou_probe_cancel(&ring, efd, &res);
	assert(r == 0);
	assert(!lacks == !gwp_iou_kernel_lacks(ring.features, res));
	nr_checks += 2;
out:
	close(efd);
	io_uring_queue_exit(&ring);
}

int main(void)
{
	test_judge();
	test_probe_here();
	printf("iou_probe: %u checks passed\n", nr_checks);
	return 0;
}
