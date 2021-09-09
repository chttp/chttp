# CHTTP Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -g -fPIC -I.
LDFLAGS=-shared
LIBFLAGS=
LIBFLAGS_TEST=-lpthread $(LIBFLAGS)

GCOV=gcov
GCOVFLAGS=-fprofile-arcs -ftest-coverage --coverage
GCOVLIBFLAGS=-lgcov
LCOV=lcov --capture --no-external --directory ./
LCOVHTML=genhtml
HTMLDIR=report

RM=rm -rf

INCLUDES=$(wildcard *.h data/*.h)
SOURCE=$(wildcard *.c dns/*.c tcp/*.c)
OBJS=$(SOURCE:.c=.o)
CLIENT=$(wildcard client/*.c)
CLIENT_OBJS=$(CLIENT:.c=.o)
TEST=$(wildcard test/*.c)
TEST_INCLUDES=$(wildcard test/*.h)
TEST_OBJS=$(TEST:.c=.o)

.PHONY:		all lib clean cleanall cleanobj cleanbin cleancov cleanreport

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
		$(LCOV) --output-file coverage.info
		$(LCOVHTML) coverage.info --output-directory $(HTMLDIR)
		$(MAKE) cleanobj cleanbin cleancov

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

clean:		cleanobj cleanbin cleancov cleanreport

cleanobj:
		$(RM) *.o */*.o *.so *.a

cleancov:
		$(RM) *.gcno */*.gcno *.gcda */*.gcda *.gcov */*.gcov coverage.info

cleanreport:
		$(RM) $(HTMLDIR)

cleanbin:
		$(RM) chttp_client chttp_test
