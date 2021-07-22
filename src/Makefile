CC=gcc
CFLAGS=-O3 -Wall -g -fPIC -I.
LDFLAGS=-shared
LIBFLAGS=
RM=rm -f

INCLUDES= \
	chttp.h \
	data/tree.h

SOURCE= \
	dns/chttp_dns_lookup.c \
	dns/chttp_dns_cache.c \
	tcp/chttp_tcp.c \
	tcp/chttp_tcp_pool.c \
	chttp_action.c \
	chttp_context.c \
	chttp_dpage.c \
	chttp_header.c \
	chttp_utils.c

CLIENT= \
	chttp_client.c

OBJS=$(SOURCE:.c=.o)
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
			$(RM) *.o dns/*.o *.so *.a chttp_client
