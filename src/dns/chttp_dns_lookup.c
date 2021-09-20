/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <limits.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>

long CHTTP_DNS_CACHE_TTL;

void
chttp_addr_init(struct chttp_addr *addr)
{
	chttp_addr_reset(addr);

	addr->magic = CHTTP_ADDR_MAGIC;
	addr->sock = -1;
}

void
chttp_addr_reset(struct chttp_addr *addr)
{
	memset(addr, 0, sizeof(*addr));
}

static void
_dns_addr_copy(struct chttp_addr *addr_dest, struct addrinfo *ai_src, int port)
{
	assert(addr_dest);
	assert(ai_src);
	assert(ai_src->ai_addr);

	chttp_addr_init(addr_dest);

	switch (ai_src->ai_addr->sa_family) {
		case AF_INET:
			addr_dest->len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			addr_dest->len = sizeof(struct sockaddr_in6);
			break;
		default:
			return;
	}

	memcpy(&addr_dest->sa, ai_src->ai_addr, addr_dest->len);

	switch (addr_dest->sa.sa_family) {
		case AF_INET:
			addr_dest->sa4.sin_port = htons(port);
			break;
		case AF_INET6:
			addr_dest->sa6.sin6_port = htons(port);
			break;
		default:
			chttp_ABORT("Incorrect address type");
	}

	addr_dest->state = CHTTP_ADDR_RESOLVED;
}

void
chttp_dns_lookup(struct chttp_context *ctx, const char *host, int port)
{
	struct addrinfo *ai_res_list;
	struct addrinfo hints;
	int ret;

	chttp_context_ok(ctx);
	assert(host && *host);
	assert(port >= 0 && port <= UINT16_MAX);

	chttp_addr_reset(&ctx->addr);

	//chttp_dns_cache_lookup(host);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, NULL, &hints, &ai_res_list);

	if (ret) {
		ctx->error = CHTTP_ERR_DNS;
		return;
	}

	//chttp_dns_cache_store(host, port);

	// Always use the first address entry on a fresh lookup
	_dns_addr_copy(&ctx->addr, ai_res_list, port);
	chttp_addr_ok(ctx);

	if (ctx->addr.state == CHTTP_ADDR_NONE) {
		ctx->error = CHTTP_ERR_DNS;
	}

	freeaddrinfo(ai_res_list);
}