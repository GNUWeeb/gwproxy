
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
	$(GWPROXY_DIR)/http1.c

GWPROXY_OBJECTS = $(GWPROXY_CC_SOURCES:%.c=%.c.o)

LIBGWPSOCKS5_TARGET = libgwpsocks5.so
LIBGWPSOCKS5_CC_SOURCES = $(GWPROXY_DIR)/socks5.c
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

ALL_TEST_TARGETS = $(LIBGWDNS_TEST_TARGET) $(LIBGWPSOCKS5_TEST_TARGET)
ALL_OBJECTS = $(GWPROXY_OBJECTS) $(LIBGWPSOCKS5_OBJECTS) $(LIBGWDNS_OBJECTS) $(LIBGWDNS_TEST_OBJECTS) $(LIBGWPSOCKS5_TEST_OBJECTS)
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
test: $(LIBGWDNS_TEST_TARGET) $(LIBGWPSOCKS5_TEST_TARGET)
	@echo "Running tests...";
	@echo "Testing libgwdns...";
	@$(IE) ./$(LIBGWDNS_TEST_TARGET);
	@echo "Testing libgwpsocks5...";
	@$(IE) ./$(LIBGWPSOCKS5_TEST_TARGET);
	@echo "Tests completed successfully.";

.PHONY: all clean test
