CC=gcc
CFLAGS=-O3 -Wall -g -fPIC -I.
LDFLAGS=-shared
LIBFLAGS=
RM=rm -f

INCLUDES=$(wildcard *.h data/*.h)
SOURCE=$(wildcard *.c dns/*.c tcp/*.c)
OBJS=$(SOURCE:.c=.o)
CLIENT=$(wildcard client/*.c)
CLIENT_OBJS=$(CLIENT:.c=.o)

.PHONY: clean lib all

all:			chttp_client lib
lib:			libchttp.so libchttp.a

chttp_client:		libchttp.a $(CLIENT_OBJS)
			$(CC) -o $@ $(CLIENT_OBJS) libchttp.a $(LIBFLAGS)

libchttp.so:		$(OBJS)
			$(CC) $(LDFLAGS) -o $@ $(OBJS)

libchttp.a:		$(OBJS)
			ar cr $@ $(OBJS)

%.o:			%.c $(INCLUDES)
			$(CC) $(CFLAGS) -c $< -o $@

clean:
			$(RM) *.o dns/*.o tcp/*.o client/*.o *.so *.a chttp_client
