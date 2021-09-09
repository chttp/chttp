# CHTTP Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -g -fPIC -I.
LDFLAGS=-shared
LIBFLAGS=
LIBFLAGS_TEST=-lpthread $(LIBFLAGS)
GCOV=gcov
GCOVFLAGS=-fprofile-arcs -ftest-coverage --coverage
GCOVLIBFLAGS=-lgcov

INCLUDES=$(wildcard *.h data/*.h)
SOURCE=$(wildcard *.c dns/*.c tcp/*.c)
OBJS=$(SOURCE:.c=.o)
CLIENT=$(wildcard client/*.c)
CLIENT_OBJS=$(CLIENT:.c=.o)
TEST=$(wildcard test/*.c)
TEST_INCLUDES=$(wildcard test/*.h)
TEST_OBJS=$(TEST:.c=.o)

.PHONY:		all clean lib cleanall

all:		chttp_client chttp_test lib
lib:		libchttp.so libchttp.a

cleanall:
		$(MAKE) clean
		$(MAKE) all CFLAGS="$(CFLAGS)" LIBFLAGS="$(LIBFLAGS)"

gcov:		CFLAGS+=$(GCOVFLAGS)
gcov:		LIBFLAGS+=$(GCOVLIBFLAGS)
gcov:		cleanall
		$(MAKE) -C .. check
		$(GCOV) -r *.c dns/*.c tcp/*.c
		$(MAKE) clean

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
		rm -f *.o */*.o *.gcno */*.gcnoi *.gcda */*.gcda *.gcov */*.gcov \
			*.so *.a chttp_client chttp_test
