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
#include <unistd.h>

static int rfd;
static FILE *wf;

/*
 * Log @msg through __pr_log() into the pipe and return the message part of
 * what came out (after the "[time][level][tid]: " header), newline included.
 */
static char *log_msg(const char *msg)
{
	static char out[65536];
	ssize_t n, tot = 0;
	char *p;

	__pr_log(wf, 3, "%s", msg);

	/* One line per call, and the pipe holds all of it. */
	do {
		n = read(rfd, out + tot, sizeof(out) - 1 - (size_t)tot);
		assert(n > 0);
		tot += n;
	} while (out[tot - 1] != '\n');
	out[tot] = '\0';

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
 * form no longer fits where the message was formatted. The longest stays
 * within what a pipe holds (64 KiB) once escaped.
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
	int fds[2];

	assert(!pipe(fds));
	rfd = fds[0];
	wf = fdopen(fds[1], "w");
	assert(wf);

	test_plain();
	test_ctl();
	test_long();
	test_escape();

	fclose(wf);
	close(rfd);
	printf("All log tests passed.\n");
	return 0;
}
