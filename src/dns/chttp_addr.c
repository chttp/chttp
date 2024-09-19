/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

void
chttp_addr_init(struct chttp_addr *addr)
{
	chttp_addr_reset(addr);

	addr->magic = CHTTP_ADDR_MAGIC;
	addr->sock = -1;

	addr->timeout_connect_ms = CHTTP_TIMEOUT_CONNECT;
	addr->timeout_transfer_ms = CHTTP_TIMEOUT_TRANSFER;
}

void
chttp_addr_reset(struct chttp_addr *addr)
{
	chttp_ZERO(addr);
}

void
chttp_addr_copy(struct chttp_addr *addr_dest, struct sockaddr *sa, int port)
{
	assert(addr_dest);
	assert(sa);
	assert(port >= 0 && port <= UINT16_MAX);

	chttp_addr_init(addr_dest);

	switch (sa->sa_family) {
		case AF_INET:
			addr_dest->len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			addr_dest->len = sizeof(struct sockaddr_in6);
			break;
		default:
			return;
	}

	memcpy(&addr_dest->sa, sa, addr_dest->len);

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
chttp_addr_move(struct chttp_addr *addr_dest, struct chttp_addr *addr)
{
	chttp_addr_ok(addr);

	chttp_addr_clone(addr_dest, addr);

	addr->state = CHTTP_ADDR_RESOLVED;
	addr->sock = -1;
	addr->nonblocking = 0;
	addr->reused = 0;
	addr->tls = 0;
	addr->tls_priv = NULL;

	chttp_addr_resolved(addr);
}

void
chttp_addr_clone(struct chttp_addr *addr_dest, struct chttp_addr *addr)
{
	chttp_addr_ok(addr);

	chttp_addr_init(addr_dest);

	addr_dest->state = addr->state;
	addr_dest->len = addr->len;
	addr_dest->sock = addr->sock;
	addr_dest->nonblocking = addr->nonblocking;
	addr_dest->reused = addr->reused;
	addr_dest->tls = addr->tls;
	addr_dest->tls_priv = addr->tls_priv;

	memcpy(&addr_dest->sa, &addr->sa, addr->len);
}

int
chttp_addr_cmp(const struct chttp_addr *a1, const struct chttp_addr *a2)
{
	chttp_addr_ok(a1);
	chttp_addr_ok(a2);

	if (a1->len != a2->len) {
		return a2->len - a1->len;
	}

	if (a1->tls != a2->tls) {
		return a2->tls - a1->tls;
	}

	return memcmp(&a1->sa, &a2->sa, a1->len);
}

int
chttp_addr_lookup(struct chttp_addr *addr, const char *host, size_t host_len, int port,
    unsigned int flags)
{
	struct addrinfo *ai_res_list;
	struct addrinfo hints;
	int ret;

	assert(addr);
	assert(host);
	assert(host_len);
	assert(port >= 0 && port <= UINT16_MAX);

	chttp_addr_reset(addr);

	if (!(flags & DNS_FRESH_LOOKUP)) {
		ret = chttp_dns_cache_lookup(host, host_len, addr, port, flags);

		if (ret) {
			chttp_addr_resolved(addr);
			return 0;
		}
	}

	chttp_ZERO(&hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, NULL, &hints, &ai_res_list);

	if (ret) {
		return 1;
	}

	// Always use the first address entry on a fresh lookup
	chttp_addr_copy(addr, ai_res_list->ai_addr, port);

	if (addr->state == CHTTP_ADDR_NONE) {
		freeaddrinfo(ai_res_list);
		return 1;
	}

	chttp_dns_cache_store(host, host_len, ai_res_list);

	freeaddrinfo(ai_res_list);

	chttp_addr_resolved(addr);

	return 0;
}