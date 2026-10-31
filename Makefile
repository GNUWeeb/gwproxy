
ifndef OPTIMIZE
	OPTIMIZE = -O2
endif
INCLUDE_FLAGS = -I./src/
DEPFLAGS = -MMD -MP -MF $@.d
LDFLAGS_SHARED = $(LDFLAGS) -shared
GWPROXY_DIR = ./src/gwproxy
LIBURING_DIR = ./src/liburing

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
else
	CFLAGS += -DNDEBUG
endif

ifeq ($(LTO),1)
	CFLAGS += -flto
	LDFLAGS += -flto
endif

ifeq ($(STATIC),1)
	LDFLAGS += -static
endif

LIBURING_TARGET = $(LIBURING_DIR)/src/liburing.a

GWPROXY_TARGET = gwproxy
GWPROXY_CC_SOURCES = \
	$(GWPROXY_DIR)/gwproxy.c \
	$(GWPROXY_DIR)/log.c \
	$(GWPROXY_DIR)/net.c \
	$(GWPROXY_DIR)/iplimit.c \
	$(GWPROXY_DIR)/upstream.c \
	$(GWPROXY_DIR)/ev/epoll.c \
	$(GWPROXY_DIR)/http1.c \
	$(GWPROXY_DIR)/http.c

GWPROXY_OBJECTS = $(GWPROXY_CC_SOURCES:%.c=%.c.o)

LIBGWPSOCKS5_TARGET = libgwpsocks5.so
LIBGWPSOCKS5_CC_SOURCES = $(GWPROXY_DIR)/socks5.c $(GWPROXY_DIR)/auth.c
LIBGWPSOCKS5_OBJECTS = $(LIBGWPSOCKS5_CC_SOURCES:%.c=%.c.o)
LIBGWPSOCKS5_TEST_TARGET = $(GWPROXY_DIR)/tests/socks5.t
LIBGWPSOCKS5_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/socks5.c
LIBGWPSOCKS5_TEST_OBJECTS = $(LIBGWPSOCKS5_TEST_CC_SOURCES:%.c=%.c.o)

# The ACL module (acl.c) is self-contained; its unit test links it directly.
LIBGWACL_CC_SOURCES = $(GWPROXY_DIR)/acl.c
LIBGWACL_OBJECTS = $(LIBGWACL_CC_SOURCES:%.c=%.c.o)
LIBGWACL_TEST_TARGET = $(GWPROXY_DIR)/tests/acl.t
LIBGWACL_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/acl.c
LIBGWACL_TEST_OBJECTS = $(LIBGWACL_TEST_CC_SOURCES:%.c=%.c.o)

LIBGWDNS_TARGET = libgwdns.so
LIBGWDNS_CC_SOURCES = $(GWPROXY_DIR)/dns.c $(GWPROXY_DIR)/dns_cache.c
LIBGWDNS_OBJECTS = $(LIBGWDNS_CC_SOURCES:%.c=%.c.o)
LIBGWDNS_TEST_TARGET = $(GWPROXY_DIR)/tests/dns.t
LIBGWDNS_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/dns.c
LIBGWDNS_TEST_OBJECTS = $(LIBGWDNS_TEST_CC_SOURCES:%.c=%.c.o)

# White-box test of the DNS cache's hash table: it #includes dns_cache.c, so it
# is built straight from its source, like http1's self-test below.
LIBGWDNS_CACHE_TEST_TARGET = $(GWPROXY_DIR)/tests/dns_cache.t

# http1's unit tests are embedded in http1.c, gated by the
# GWNET_HTTP1_TESTS/GWNET_HTTP1_RUN_TESTS macros, so the self-test binary
# is built straight from http1.c rather than a separate test source.
LIBGWHTTP1_TEST_TARGET = $(GWPROXY_DIR)/tests/http1.t

# The HTTP proxy module (http.c) is linked against the HTTP/1 parser (http1.c)
# and the credential store (auth.c); its unit tests live in a separate source.
LIBGWHTTP_TEST_TARGET = $(GWPROXY_DIR)/tests/http.t
LIBGWHTTP_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/http.c
LIBGWHTTP_TEST_OBJECTS = $(LIBGWHTTP_TEST_CC_SOURCES:%.c=%.c.o)
LIBGWHTTP_OBJECTS = $(GWPROXY_DIR)/http.c.o $(GWPROXY_DIR)/http1.c.o \
		    $(GWPROXY_DIR)/auth.c.o

# The logger (log.c), linked straight into its unit test.
LIBGWLOG_TEST_TARGET = $(GWPROXY_DIR)/tests/log.t
LIBGWLOG_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/log.c
LIBGWLOG_TEST_OBJECTS = $(LIBGWLOG_TEST_CC_SOURCES:%.c=%.c.o)

# The per-client-address connection counter (iplimit.c), linked straight into
# its unit test.
LIBGWIPLIM_TEST_TARGET = $(GWPROXY_DIR)/tests/iplimit.t
LIBGWIPLIM_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/iplimit.c
LIBGWIPLIM_TEST_OBJECTS = $(LIBGWIPLIM_TEST_CC_SOURCES:%.c=%.c.o)

# The epoll loop's timer heap (ev/tmr.h) is header-only, so its unit test is
# built straight from its source.
GWTMR_TEST_TARGET = $(GWPROXY_DIR)/tests/tmr.t

ALL_TEST_TARGETS = $(LIBGWDNS_TEST_TARGET) $(LIBGWDNS_CACHE_TEST_TARGET) \
		   $(LIBGWPSOCKS5_TEST_TARGET) \
		   $(LIBGWHTTP1_TEST_TARGET) $(LIBGWHTTP_TEST_TARGET) \
		   $(LIBGWACL_TEST_TARGET) $(LIBGWLOG_TEST_TARGET) \
		   $(LIBGWIPLIM_TEST_TARGET) $(GWTMR_TEST_TARGET)
ALL_OBJECTS = $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS) $(LIBGWDNS_OBJECTS) $(LIBGWDNS_TEST_OBJECTS) $(LIBGWPSOCKS5_TEST_OBJECTS) $(LIBGWHTTP_TEST_OBJECTS) $(LIBGWACL_OBJECTS) $(LIBGWACL_TEST_OBJECTS) $(LIBGWLOG_TEST_OBJECTS) $(LIBGWIPLIM_TEST_OBJECTS)
ALL_TARGETS = $(GWPROXY_TARGET) $(LIBGWPSOCKS5_TARGET) $(LIBGWDNS_TARGET) $(ALL_TEST_TARGETS)
ALL_DEPFILES = $(ALL_OBJECTS:.o=.o.d)

ALL_GWPROXY_OBJECTS = $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS) $(LIBGWDNS_OBJECTS) $(LIBGWACL_OBJECTS)

all: $(GWPROXY_TARGET) $(LIBGWPSOCKS5_TARGET) $(LIBGWDNS_TARGET)

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
config.make: configure
	@if [ ! -e "$@" ]; then						\
	  echo "Running configure ...";					\
	  LDFLAGS="$(USER_LDFLAGS)"					\
	      LIB_LDFLAGS="$(USER_LIB_LDFLAGS)"				\
	      CFLAGS="$(USER_CFLAGS)" 					\
	      CXXFLAGS="$(USER_CXXFLAGS)"				\
	      ./configure;						\
	else								\
	  echo "$@ is out-of-date";					\
	  echo "Running configure ...";					\
	  LDFLAGS="$(USER_LDFLAGS)"					\
	      LIB_LDFLAGS="$(USER_LIB_LDFLAGS)"				\
	      CFLAGS="$(USER_CFLAGS)" 					\
	      CXXFLAGS="$(USER_CXXFLAGS)"				\
	      sed -n "/.*Configured with/s/[^:]*: //p" "$@" | sh;	\
	fi;

endif
endif
-include config.make
LIBS=$(LIB_LDFLAGS)

ifeq ($(CONFIG_NEW_DNS_RESOLVER),y)
GWPROXY_CC_SOURCES += \
	$(GWPROXY_DIR)/dns_parser.c \
	$(GWPROXY_DIR)/dns_resolver.c

# The raw DNS parser's self-test is embedded in dns_parser.c (RUNTEST).
DNS_PARSER_TEST_TARGET = $(GWPROXY_DIR)/tests/dns_parser.t
ALL_TEST_TARGETS += $(DNS_PARSER_TEST_TARGET)
endif

ifeq ($(CONFIG_HTTPS),y)
GWPROXY_CC_SOURCES += $(GWPROXY_DIR)/ssl.c
SSL_TEST_TARGET = $(GWPROXY_DIR)/tests/ssl.t
SSL_TEST_OBJECTS = $(GWPROXY_DIR)/tests/ssl.c.o
ALL_TEST_TARGETS += $(SSL_TEST_TARGET)
ALL_OBJECTS += $(SSL_TEST_OBJECTS)
RUN_SSL_TEST = @echo "Testing ssl..."; $(IE) ./$(SSL_TEST_TARGET);
endif

ifeq ($(CONFIG_IO_URING),y)
	GWPROXY_CC_SOURCES += $(GWPROXY_DIR)/ev/io_uring.c
	ALL_GWPROXY_OBJECTS += $(LIBURING_TARGET)

# Make sure to build liburing first as it needs liburing.h.
	EXTRA_DEPS += $(LIBURING_TARGET)

$(LIBURING_DIR)/Makefile:
	git submodule update --init --recursive;

#
# liburing keeps its own configuration, in config-host.mak, and it outlives
# ours: "make clean" here only descends into the submodule while
# CONFIG_IO_URING is still set, and a caller that removes config.make first --
# .github/scripts/ci.sh does, deliberately -- leaves both that file and
# liburing.a behind. Only the sanitized branch below ever wrote the submodule's
# configuration, and nothing put it back afterwards: once a tree had built with
# --sanitize, every later build reused an instrumented liburing, and the first
# one without --sanitize failed to link against it with a few thousand
# undefined __asan_*/__ubsan_* symbols.
#
# So depend on config.make, which is rewritten whenever this tree is
# reconfigured, and start from a clean submodule each time. liburing's own
# clean removes config-host.mak and its Makefile regenerates it with defaults,
# so the unsanitized case needs nothing here -- it just must not inherit the
# old one.
#
# The cost is rebuilding liburing on every reconfigure. It is a small library,
# and the alternative is a build whose correctness depends on the order the
# variants happened to run in.
#
$(LIBURING_TARGET): $(LIBURING_DIR)/Makefile config.make
	@$(MAKE) -C $(LIBURING_DIR) clean
ifeq ($(CONFIG_SANITIZE),y)
	cd $(LIBURING_DIR) && ./configure --enable-sanitizer;
endif
	@$(MAKE) -C $(LIBURING_DIR) library
endif # ifeq ($(CONFIG_IO_URING),y)

$(GWPROXY_TARGET): $(ALL_GWPROXY_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)


#
# TODO(*): Test against the *.so files. Currently, the tests in
#          `tests/` are built against the static objects.
#
$(LIBGWPSOCKS5_TARGET): $(LIBGWPSOCKS5_OBJECTS)
	$(CC) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS)

$(LIBGWPSOCKS5_TEST_TARGET): $(LIBGWPSOCKS5_OBJECTS) $(LIBGWPSOCKS5_TEST_OBJECTS) $(LIBGWPSOCKS5_TARGET)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(LIBGWACL_TEST_TARGET): $(LIBGWACL_OBJECTS) $(LIBGWACL_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(LIBGWDNS_TARGET): $(LIBGWDNS_OBJECTS)
	$(CC) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS)

$(LIBGWDNS_TEST_TARGET): $(LIBGWDNS_OBJECTS) $(LIBGWDNS_TEST_OBJECTS) $(LIBGWDNS_TARGET)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(GWPROXY_DIR)/tests/dns_parser.t: $(GWPROXY_DIR)/dns_parser.c $(GWPROXY_DIR)/dns_parser.h $(GWPROXY_DIR)/net.c $(EXTRA_DEPS)
	$(CC) $(CFLAGS) -DRUNTEST $(LDFLAGS) -o $@ $(GWPROXY_DIR)/dns_parser.c $(GWPROXY_DIR)/net.c $(LIBS)

$(LIBGWDNS_CACHE_TEST_TARGET): $(GWPROXY_DIR)/tests/dns_cache.c $(GWPROXY_DIR)/dns_cache.c $(GWPROXY_DIR)/dns_cache.h $(EXTRA_DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(LIBGWHTTP1_TEST_TARGET): $(GWPROXY_DIR)/http1.c $(GWPROXY_DIR)/http1.h $(GWPROXY_DIR)/common.h $(EXTRA_DEPS)
	$(CC) $(CFLAGS) -DGWNET_HTTP1_TESTS -DGWNET_HTTP1_RUN_TESTS $(LDFLAGS) -o $@ $< $(LIBS)

$(LIBGWHTTP_TEST_TARGET): $(LIBGWHTTP_OBJECTS) $(LIBGWHTTP_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(LIBGWLOG_TEST_TARGET): $(GWPROXY_DIR)/log.c.o $(LIBGWLOG_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(LIBGWIPLIM_TEST_TARGET): $(GWPROXY_DIR)/iplimit.c.o $(LIBGWIPLIM_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(GWTMR_TEST_TARGET): $(GWPROXY_DIR)/tests/tmr.c $(GWPROXY_DIR)/ev/tmr.h $(GWPROXY_DIR)/gwproxy.h $(EXTRA_DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

ifeq ($(CONFIG_HTTPS),y)
$(SSL_TEST_TARGET): $(GWPROXY_DIR)/ssl.c.o $(SSL_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
endif

%.c.o: %.c $(EXTRA_DEPS)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

-include $(ALL_DEPFILES)

TO_BE_REMOVED = $(ALL_OBJECTS) $(ALL_TARGETS) $(ALL_DEPFILES)

clean:
	rm -f $(TO_BE_REMOVED)
ifeq ($(CONFIG_IO_URING),y)
	@$(MAKE) -C $(LIBURING_DIR) clean
endif

IE=LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(shell pwd)

#
# Tests run one per make target, so `make -jN test` runs N of them at once and
# make itself schedules the parallelism -- there is no second job-control knob
# to keep in sync. Each test writes a result file; t/run-one.sh always exits 0
# so one failure does not stop the rest, and t/summary.sh turns the collected
# results into the final verdict.
#
TEST_OUT = .test-out
INTEG_SRCS = $(sort $(wildcard t/[0-9]*.sh))
INTEG_RESULTS = $(patsubst t/%.sh,$(TEST_OUT)/integ-%.res,$(INTEG_SRCS))
UNIT_RESULTS = $(patsubst $(GWPROXY_DIR)/tests/%.t,$(TEST_OUT)/unit-%.res,$(ALL_TEST_TARGETS))

$(TEST_OUT)/unit-%.res: $(GWPROXY_DIR)/tests/%.t
	@./t/run-one.sh unit "$*" "$<" "$@"

$(TEST_OUT)/integ-%.res: t/%.sh $(GWPROXY_TARGET)
	@GWPROXY=./$(GWPROXY_TARGET) ./t/run-one.sh integ "$*" "$<" "$@"

test: test-unit test-integration
	@echo "All tests completed successfully.";

# The results are deleted first so a re-run really re-runs: a test result is
# not a build artifact that can be considered up to date.
test-unit: $(ALL_TEST_TARGETS)
	@echo "Running unit tests...";
	@rm -rf $(TEST_OUT)/unit-*
	@mkdir -p $(TEST_OUT)
	@$(MAKE) --no-print-directory $(UNIT_RESULTS)
	@./t/summary.sh unit $(TEST_OUT) --only unit

test-integration: $(GWPROXY_TARGET)
	@echo "Running integration tests...";
	@rm -rf $(TEST_OUT)/integ-*
	@mkdir -p $(TEST_OUT)
	@$(MAKE) --no-print-directory $(INTEG_RESULTS)
	@./t/summary.sh integration $(TEST_OUT) --only integ

.PHONY: all clean test test-unit test-integration
