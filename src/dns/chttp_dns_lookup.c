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
_dns_addr_copy(struct chttp_addr *addr_dest, struct addrinfo *ai_src, int port)
{
	assert(addr_dest);
	assert(ai_src);
	assert(ai_src->ai_addr);

	addr_dest->magic = 0;
	addr_dest->sock = -1;

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

	addr_dest->magic = CHTTP_ADDR_MAGIC;
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
}

void
chttp_dns_lookup(struct chttp_context *ctx, const char *host, int port)
{
	struct addrinfo *ai_res_list;
	struct addrinfo hints;
	int ret;

	chttp_context_ok(ctx);
	assert(host && *host);
	assert(port >= 0 && port <= INT16_MAX);

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

	/*
	struct addrinfo *ai_res;
	char tmp[128];
	for (ai_res = ai_res_list; ai_res; ai_res = ai_res->ai_next) {
		switch (ai_res->ai_addr->sa_family) {
			case AF_INET:
				inet_ntop(AF_INET, &(((struct sockaddr_in*)ai_res->ai_addr)->sin_addr),
				    tmp, sizeof(tmp));
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, &(((struct sockaddr_in6*)ai_res->ai_addr)->sin6_addr),
				    tmp, sizeof(tmp));
				break;
			default:
				strncpy(tmp, "unknown address", sizeof(tmp));
				break;
		}
		printf("*** found %s\n", tmp);
	}
	*/

	// Always use the first address entry on a fresh lookup
	_dns_addr_copy(&ctx->addr, ai_res_list, port);

	if (!ctx->addr.magic) {
		ctx->error = CHTTP_ERR_DNS;
	}

	freeaddrinfo(ai_res_list);
}
