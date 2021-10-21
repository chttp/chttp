/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

void
chttp_dns_lookup(struct chttp_context *ctx, const char *host, size_t host_len, int port,
    int fresh)
{
	int ret;

	chttp_context_ok(ctx);

	ret = chttp_addr_lookup(&ctx->addr, host, host_len, port, fresh);

	if (ret) {
		ctx->error = CHTTP_ERR_DNS;
	}
}