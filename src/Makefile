# CHTTP Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -g -fPIC -I.
LDFLAGS=-shared
LIBFLAGS=
RM=rm -f

INCLUDES=$(wildcard *.h data/*.h)
SOURCE=$(wildcard *.c dns/*.c tcp/*.c)
OBJS=$(SOURCE:.c=.o)
CLIENT=$(wildcard client/*.c)
CLIENT_OBJS=$(CLIENT:.c=.o)
TEST=$(wildcard test/*.c)
TEST_INCLUDES=$(wildcard test/*.h)
TEST_OBJS=$(TEST:.c=.o)

.PHONY:		all clean lib allclean

all:		chttp_client chttp_test lib
lib:		libchttp.so libchttp.a

allclean:
		$(MAKE) clean
		$(MAKE) all

chttp_client:	libchttp.a $(CLIENT_OBJS)
		$(CC) -o $@ $(CLIENT_OBJS) libchttp.a $(LIBFLAGS)

chttp_test:	libchttp.a $(TEST_OBJS)
		$(CC) -o $@ $(TEST_OBJS) libchttp.a $(LIBFLAGS)

libchttp.so:	$(OBJS)
		$(CC) $(LDFLAGS) -o $@ $(OBJS)

libchttp.a:	$(OBJS)
		ar cr $@ $(OBJS)

%.o:		%.c $(INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

test/%.o:	test/%.c $(INCLUDES) $(TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		$(RM) *.o dns/*.o tcp/*.o client/*.o test/*.o \
		*.so *.a chttp_client chttp_test
