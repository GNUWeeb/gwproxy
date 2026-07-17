
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

LIBGWDNS_TARGET = libgwdns.so
LIBGWDNS_CC_SOURCES = $(GWPROXY_DIR)/dns.c $(GWPROXY_DIR)/dns_cache.c
LIBGWDNS_OBJECTS = $(LIBGWDNS_CC_SOURCES:%.c=%.c.o)
LIBGWDNS_TEST_TARGET = $(GWPROXY_DIR)/tests/dns.t
LIBGWDNS_TEST_CC_SOURCES = $(GWPROXY_DIR)/tests/dns.c
LIBGWDNS_TEST_OBJECTS = $(LIBGWDNS_TEST_CC_SOURCES:%.c=%.c.o)

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

ALL_TEST_TARGETS = $(LIBGWDNS_TEST_TARGET) $(LIBGWPSOCKS5_TEST_TARGET) \
		   $(LIBGWHTTP1_TEST_TARGET) $(LIBGWHTTP_TEST_TARGET)
ALL_OBJECTS = $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS) $(LIBGWDNS_OBJECTS) $(LIBGWDNS_TEST_OBJECTS) $(LIBGWPSOCKS5_TEST_OBJECTS) $(LIBGWHTTP_TEST_OBJECTS)
ALL_TARGETS = $(GWPROXY_TARGET) $(LIBGWPSOCKS5_TARGET) $(LIBGWDNS_TARGET) $(ALL_TEST_TARGETS)
ALL_DEPFILES = $(ALL_OBJECTS:.o=.o.d)

ALL_GWPROXY_OBJECTS = $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS) $(LIBGWDNS_OBJECTS)

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
endif

ifeq ($(CONFIG_IO_URING),y)
	GWPROXY_CC_SOURCES += $(GWPROXY_DIR)/ev/io_uring.c
	ALL_GWPROXY_OBJECTS += $(LIBURING_TARGET)

# Make sure to build liburing first as it needs liburing.h.
	EXTRA_DEPS += $(LIBURING_TARGET)

$(LIBURING_DIR)/Makefile:
	git submodule update --init --recursive;

$(LIBURING_TARGET): $(LIBURING_DIR)/Makefile
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

$(LIBGWDNS_TARGET): $(LIBGWDNS_OBJECTS)
	$(CC) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS)

$(LIBGWDNS_TEST_TARGET): $(LIBGWDNS_OBJECTS) $(LIBGWDNS_TEST_OBJECTS) $(LIBGWDNS_TARGET)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(LIBGWHTTP1_TEST_TARGET): $(GWPROXY_DIR)/http1.c $(GWPROXY_DIR)/http1.h $(GWPROXY_DIR)/common.h $(EXTRA_DEPS)
	$(CC) $(CFLAGS) -DGWNET_HTTP1_TESTS -DGWNET_HTTP1_RUN_TESTS $(LDFLAGS) -o $@ $< $(LIBS)

$(LIBGWHTTP_TEST_TARGET): $(LIBGWHTTP_OBJECTS) $(LIBGWHTTP_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

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
test: test-unit test-integration
	@echo "All tests completed successfully.";

test-unit: $(LIBGWDNS_TEST_TARGET) $(LIBGWPSOCKS5_TEST_TARGET) $(LIBGWHTTP1_TEST_TARGET) $(LIBGWHTTP_TEST_TARGET)
	@echo "Running unit tests...";
	@echo "Testing libgwdns...";
	@$(IE) ./$(LIBGWDNS_TEST_TARGET);
	@echo "Testing libgwpsocks5...";
	@$(IE) ./$(LIBGWPSOCKS5_TEST_TARGET);
	@echo "Testing http1...";
	@$(IE) ./$(LIBGWHTTP1_TEST_TARGET);
	@echo "Testing http...";
	@$(IE) ./$(LIBGWHTTP_TEST_TARGET);
	@echo "Unit tests completed.";

test-integration: $(GWPROXY_TARGET)
	@echo "Running integration tests...";
	@GWPROXY=./$(GWPROXY_TARGET) ./t/run.sh;

.PHONY: all clean test test-unit test-integration
