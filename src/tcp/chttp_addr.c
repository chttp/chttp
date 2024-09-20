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

void
chttp_addr_connect(struct chttp_context *ctx)
{
	int ret;

	chttp_context_ok(ctx);
	chttp_addr_resolved(&ctx->addr);

	if (!ctx->fresh_conn) {
		ret = chttp_tcp_pool_lookup(&ctx->addr);

		if (ret) {
			chttp_addr_connected(&ctx->addr);
			return;
		}
	}

	ret = chttp_tcp_connect(&ctx->addr);

	if (ret) {
		chttp_error(ctx, CHTTP_ERR_CONNECT);
		return;
	}

	if (ctx->addr.tls) {
		chttp_tls_connect(ctx);
	}

	chttp_addr_connected(&ctx->addr);
}

void
chttp_addr_try_close(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_RESP_BODY);
	assert(ctx->state < CHTTP_STATE_CLOSED);

	if (ctx->state == CHTTP_STATE_IDLE && ctx->close) {
		chttp_tcp_close(&ctx->addr);
		ctx->state = CHTTP_STATE_CLOSED;
	}
}