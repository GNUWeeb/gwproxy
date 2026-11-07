// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unit tests for the logger: whatever a message carries, one call writes
 * exactly one line, with control bytes escaped; and for gwp_log_escape().
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/log.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static FILE *wf;
static off_t rpos;

/*
 * Log @msg through __pr_log() and return the message part of what came out
 * (after the "[time][level][tid]: " header), newline included.
 *
 * The log goes to a memory file, read back from where the last line ended.
 * Not a pipe: this thread both writes and reads, so a line longer than the
 * pipe holds would block the write for good. A pipe usually holds 64 KiB,
 * but only a page or two once the user has used up the pages that
 * fs.pipe-user-pages-soft allows, as on a busy test host.
 */
static char *log_msg(const char *msg)
{
	static char out[65536];
	ssize_t n, tot = 0;
	char *p;

	__pr_log(wf, 3, "%s", msg);

	for (;;) {
		n = pread(fileno(wf), out + tot, sizeof(out) - 1 - (size_t)tot,
			  rpos + tot);
		assert(n >= 0);
		if (!n)
			break;
		tot += n;
	}
	rpos += tot;
	out[tot] = '\0';

	/* One call wrote exactly one line. */
	assert(tot > 0 && out[tot - 1] == '\n');
	assert(strchr(out, '\n') == out + tot - 1);

	p = strstr(out, "]: ");
	assert(p);
	return p + 3;
}

static void test_plain(void)
{
	assert(!strcmp(log_msg("hello world"), "hello world\n"));
	assert(!strcmp(log_msg(""), "\n"));
	/* Printable bytes and bytes above 0x7f pass unchanged. */
	assert(!strcmp(log_msg("a\\x0a \"q\" \xc3\xa9"), "a\\x0a \"q\" \xc3\xa9\n"));
}

static void test_ctl(void)
{
	assert(!strcmp(log_msg("x\ny"), "x\\x0ay\n"));
	assert(!strcmp(log_msg("\r\n[2026-01-01 00:00:00][info  ][00000001]: forged"),
		       "\\x0d\\x0a[2026-01-01 00:00:00][info  ][00000001]: forged\n"));
	assert(!strcmp(log_msg("\t\x1b[31m\x7f\x01"),
		       "\\x09\\x1b[31m\\x7f\\x01\n"));
	assert(!strcmp(log_msg("\n"), "\\x0a\n"));
}

/*
 * Messages near and past the size of the logger's stack buffer: the escaped
 * form no longer fits where the message was formatted.
 */
static void test_long(void)
{
	static const size_t lens[] = { 4000, 4060, 4096, 5000, 12000 };
	size_t i, j, k, len;
	char *msg, *exp, *got;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		len = lens[i];
		msg = malloc(len + 1);
		exp = malloc(len * 4 + 2);
		assert(msg && exp);

		for (j = 0; j < len; j++)
			msg[j] = (j % 7 == 3) ? '\n' : (char)('a' + j % 26);
		msg[len] = '\0';

		for (j = 0, k = 0; j < len; j++) {
			if (msg[j] == '\n') {
				memcpy(exp + k, "\\x0a", 4);
				k += 4;
			} else {
				exp[k++] = msg[j];
			}
		}
		exp[k++] = '\n';
		exp[k] = '\0';

		got = log_msg(msg);
		assert(!strcmp(got, exp));
		free(msg);
		free(exp);
	}
}

static void test_escape(void)
{
	char buf[GWP_LOG_ESC_SIZE(16)];

	assert(!strcmp(gwp_log_escape(buf, "user", 4), "user"));
	assert(!strcmp(gwp_log_escape(buf, "", 0), ""));
	assert(!strcmp(gwp_log_escape(buf, "a b~", 4), "a b~"));
	/* NUL is a byte like any other; the length says where it ends. */
	assert(!strcmp(gwp_log_escape(buf, "u\0s", 3), "u\\x00s"));
	assert(!strcmp(gwp_log_escape(buf, "\r\n\x7f", 3), "\\x0d\\x0a\\x7f"));
	assert(!strcmp(gwp_log_escape(buf, "\"\\", 2), "\\x22\\x5c"));
	assert(!strcmp(gwp_log_escape(buf, "\xc3\xa9\xff", 3), "\\xc3\\xa9\\xff"));
	/* Every byte escaped: the worst case fills the buffer exactly. */
	memset(buf, 'z', sizeof(buf));
	gwp_log_escape(buf, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n", 16);
	assert(strlen(buf) == sizeof(buf) - 1);
}

int main(void)
{
	int fd = memfd_create("log-test", MFD_CLOEXEC);

	assert(fd >= 0);
	wf = fdopen(fd, "w");
	assert(wf);

	test_plain();
	test_ctl();
	test_long();
	test_escape();

	fclose(wf);
	printf("All log tests passed.\n");
	return 0;
}
