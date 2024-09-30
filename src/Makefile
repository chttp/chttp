# CHTTP Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -g -fPIC -I. -fno-omit-frame-pointer
LDFLAGS=-shared
LIBFLAGS=
LIBFLAGS_TEST=-lpthread $(LIBFLAGS)

INCLUDES=$(wildcard *.h data/*.h memory/*.h dns/*.h tls/*.h compress/*.h)
SOURCE=$(wildcard *.c memory/*.c dns/*.c tcp/*.c tls/*.c compress/*.c)
OBJS=$(SOURCE:.c=.o)
CLIENT=$(wildcard client/*.c)
CLIENT_OBJS=$(CLIENT:.c=.o)
TEST=$(wildcard test/*.c)
TEST_INCLUDES=$(wildcard test/*.h)
TEST_OBJS=$(TEST:.c=.o)

RM=rm -f
RMDIR=rm -rf
NULL=/dev/null
TEST_TRUE= > $(NULL) 2>&1 && echo true
TCC=$(CC) -x c - -o $(NULL)

# Detect openssl
OPENSSL_C='\#include <openssl/ssl.h>\nint main() {SSL *ssl;}'
OPENSSL_CFLAGS=-DCHTTP_OPENSSL
OPENSSL_LIB=-lssl
OPENSSL=$(shell printf $(OPENSSL_C) | $(TCC) $(OPENSSL_LIB) $(TEST_TRUE))
ifeq ($(OPENSSL),true)
	CFLAGS+=$(OPENSSL_CFLAGS)
	LIBFLAGS+=$(OPENSSL_LIB)
endif

# Detect zlib
ZLIB_C='\#include <zlib.h>\nint main() {zlibVersion();}'
ZLIB_CFLAGS=-DCHTTP_ZLIB
ZLIB_LIB=-lz
ZLIB=$(shell printf $(ZLIB_C) | $(TCC) $(ZLIB_LIB) $(TEST_TRUE))
ifeq ($(ZLIB),true)
	CFLAGS+=$(ZLIB_CFLAGS)
	LIBFLAGS+=$(ZLIB_LIB)
endif

# gcov
GCOV=gcov
GCOVFLAGS=-fprofile-arcs -ftest-coverage --coverage
GCOVLIBFLAGS=-lgcov
LCOV=lcov --capture --no-external --directory ./
LCOVHTML=genhtml
HTMLDIR=report

.PHONY:		all lib gcov clean cleanall

all:		chttp_client chttp_test lib
lib:		libchttp.so libchttp.a

chttp_client:	libchttp.a $(CLIENT_OBJS)
		$(CC) -o $@ $(CLIENT_OBJS) libchttp.a $(LIBFLAGS)

chttp_test:	libchttp.a $(TEST_OBJS)
		$(CC) -o $@ $(TEST_OBJS) libchttp.a $(LIBFLAGS_TEST)

libchttp.so:	$(OBJS)
		$(CC) $(LDFLAGS) -o $@ $(OBJS)

libchttp.a:	$(OBJS)
		ar cr $@ $(OBJS)

%.o:		%.c $(INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

test/%.o:	test/%.c $(INCLUDES) $(TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		$(RM) *.o */*.o *.so *.a
		$(RM) chttp_client chttp_test
		$(RM) *.gcno */*.gcno *.gcda */*.gcda *.gcov */*.gcov
		$(RM) coverage.info gcov.data
		$(RMDIR) $(HTMLDIR)

cleanall:
		$(MAKE) clean
		$(MAKE) all

gcov:		gcov.data
		$(GCOV) -r *.c dns/*.c tcp/*.c
		$(LCOV) --output-file coverage.info
		$(LCOVHTML) coverage.info --output-directory $(HTMLDIR)

gcov.data:	CFLAGS+=$(GCOVFLAGS)
gcov.data:	LIBFLAGS+=$(GCOVLIBFLAGS)
gcov.data:
		$(MAKE) cleanall CFLAGS="$(CFLAGS)" LIBFLAGS="$(LIBFLAGS)"
		$(MAKE) -C .. check V=vv
		touch gcov.data
