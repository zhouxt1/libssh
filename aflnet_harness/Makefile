# Build the single-connection AFLNet harness for libssh.
#
# Assumes libssh has been configured + built as a static lib in ../build/
# (i.e. cd .. && mkdir build && cmake -DBUILD_SHARED_LIBS=OFF ... && make ssh).
#
# Override LIBSSH_SRC / LIBSSH_BUILD on the make command line if your tree
# layout differs from the default in-source ../build/ location.

LIBSSH_SRC   ?= $(CURDIR)/..
LIBSSH_BUILD ?= $(LIBSSH_SRC)/build

# libssh.a is ASAN-instrumented (built with AFL_USE_ASAN=1), so the harness
# must compile AND link with -fsanitize=address — otherwise libssh.a's
# __asan_* references stay unresolved.
CC       = afl-clang-fast
ASAN     = -fsanitize=address
CFLAGS  ?= -g -O2
CPPFLAGS = -DLIBSSH_STATIC=1 \
           -I$(LIBSSH_SRC)/include \
           -I$(LIBSSH_BUILD)/include
LDLIBS   = $(LIBSSH_BUILD)/src/libssh.a \
           -lssl -lcrypto -lz -lpthread -ldl

aflnet_server: aflnet_server.c $(LIBSSH_BUILD)/src/libssh.a
	$(CC) $(CFLAGS) $(ASAN) $(CPPFLAGS) -o $@ aflnet_server.c $(LDLIBS)

$(LIBSSH_BUILD)/src/libssh.a:
	@echo "libssh static lib not found at $@" >&2
	@echo "Build libssh first (see SSH_libssh.md)." >&2
	@exit 1

clean:
	rm -f aflnet_server

.PHONY: clean
