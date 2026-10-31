#include <gwproxy/common.h>
#include <gwproxy/log.h>
#include <gwproxy/syscall.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

/*
 * Per-thread state, so a log line costs no syscall but its write(2): the
 * thread id never changes, and the timestamp only has to be formatted again
 * when the second changes (localtime_r() takes glibc's global timezone lock).
 */
static __thread pid_t log_tid;
static __thread time_t log_sec = (time_t)-1;
static __thread char log_time[32];

static const char *log_time_str(void)
{
	time_t now = time(NULL);
	struct tm tm;

	if (now != log_sec) {
		log_sec = now;
		if (likely(localtime_r(&now, &tm)))
			strftime(log_time, sizeof(log_time),
				 "%Y-%m-%d %H:%M:%S", &tm);
		else
			log_time[0] = '\0';
	}
	return log_time;
}

static void log_write(int fd, const char *buf, size_t len)
{
	ssize_t r;

	while (len) {
		r = __sys_write(fd, buf, len);
		if (r < 0) {
			if (r == -EINTR)
				continue;
			return;
		}
		buf += r;
		len -= (size_t)r;
	}
}

char *gwp_log_escape(char *dst, const void *src, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	const unsigned char *s = src;
	char *d = dst;
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned char c = s[i];

		if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') {
			*d++ = (char)c;
			continue;
		}
		*d++ = '\\';
		*d++ = 'x';
		*d++ = hex[c >> 4];
		*d++ = hex[c & 0xf];
	}
	*d = '\0';
	return dst;
}

static inline bool log_is_ctl(unsigned char c)
{
	return c < 0x20 || c == 0x7f;
}

/*
 * Rewrite each control byte of the @len bytes at @s as "\xHH", in place,
 * working back from the end. The buffer must have room for @len + 3 * @nr_ctl
 * bytes, @nr_ctl being the number of control bytes in it. Returns the new
 * length.
 */
static size_t log_escape_ctl(char *s, size_t len, size_t nr_ctl)
{
	static const char hex[] = "0123456789abcdef";
	char *src = s + len, *dst = src + 3 * nr_ctl;

	while (dst > src) {
		unsigned char c = (unsigned char)*--src;

		if (!log_is_ctl(c)) {
			*--dst = (char)c;
			continue;
		}
		*--dst = hex[c & 0xf];
		*--dst = hex[c >> 4];
		*--dst = 'x';
		*--dst = '\\';
	}
	return len + 3 * nr_ctl;
}

/*
 * The whole line is formatted once into one buffer and handed to the kernel
 * with a single write(2), bypassing stdio: no FILE lock for the workers to
 * serialise on, no second formatting pass, and no flush. A regular log file
 * is opened with O_APPEND (fopen "a"), so lines from different workers never
 * interleave.
 *
 * Control bytes in the message (CR, LF, ESC, ...) are written as "\xHH":
 * messages carry strings that come from clients, and a raw line break would
 * let a client end the line and append entries of its own. The trailing '\n'
 * is added here, so no format needs one.
 */
__attribute__((__format__(printf, 3, 4)))
void __pr_log(FILE *handle, int level, const char *fmt, ...)
{
	char loc_buf[4096], *pb = loc_buf, *nb;
	size_t hlen, room, mlen, cap, nr_ctl = 0, i;
	va_list ap, ap2;
	const char *ls;
	int r;

	if (!handle)
		return;

	switch (level) {
	case 1:  ls = "error "; break;
	case 2:  ls = "warn  "; break;
	case 3:  ls = "info  "; break;
	case 4:  ls = "debug "; break;
	default: ls = "????? "; break;
	}

	if (unlikely(!log_tid))
		log_tid = __sys_gettid();

	r = snprintf(loc_buf, sizeof(loc_buf), "[%s][%s][%08d]: ",
		     log_time_str(), ls, log_tid);
	if (unlikely(r < 0 || (size_t)r >= sizeof(loc_buf)))
		return;
	hlen = (size_t)r;
	/* Keep one byte for the '\n' that replaces the terminator. */
	room = sizeof(loc_buf) - hlen - 1;

	va_start(ap, fmt);
	va_copy(ap2, ap);
	r = vsnprintf(loc_buf + hlen, room, fmt, ap);
	if (unlikely(r < 0))
		goto out;	/* bad format or conversion: nothing to print */
	if (unlikely((size_t)r >= room)) {
		pb = malloc(hlen + (size_t)r + 2);
		if (!pb)
			goto out;

		memcpy(pb, loc_buf, hlen);
		vsnprintf(pb + hlen, (size_t)r + 1, fmt, ap2);
	}
	mlen = (size_t)r;
	cap = pb == loc_buf ? sizeof(loc_buf) : hlen + mlen + 2;

	for (i = 0; i < mlen; i++)
		nr_ctl += log_is_ctl((unsigned char)pb[hlen + i]);

	if (unlikely(nr_ctl)) {
		if (hlen + mlen + 3 * nr_ctl + 1 > cap) {
			nb = malloc(hlen + mlen + 3 * nr_ctl + 1);
			if (nb) {
				memcpy(nb, pb, hlen + mlen);
				if (pb != loc_buf)
					free(pb);
				pb = nb;
			}
		} else {
			nb = pb;
		}

		if (nb) {
			mlen = log_escape_ctl(pb + hlen, mlen, nr_ctl);
		} else {
			/* No room to escape: still never pass one through. */
			for (i = 0; i < mlen; i++) {
				if (log_is_ctl((unsigned char)pb[hlen + i]))
					pb[hlen + i] = '?';
			}
		}
	}

	pb[hlen + mlen] = '\n';
	log_write(fileno(handle), pb, hlen + mlen + 1);
	if (unlikely(pb != loc_buf))
		free(pb);
out:
	va_end(ap2);
	va_end(ap);
}
