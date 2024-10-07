/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "compress/chttp_gzip.h"
#include "dns/chttp_dns.h"
#include "tls/chttp_tls.h"

static void
_finalize_request(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_INIT_HEADER);

	if (!ctx->has_host && ctx->version > CHTTP_H_VERSION_1_0) {
		if(ctx->hostname.dpage) {
			assert(ctx->hostname.length);
			chttp_add_header(ctx, "Host",
				(char*)chttp_dpage_ptr_convert(ctx, &ctx->hostname));
		} else {
			chttp_ABORT("host header is missing");
		}
		assert(ctx->has_host);
	}

	if (ctx->gzip) {
		chttp_add_header(ctx, "Accept-Encoding", "gzip");
	}

	chttp_dpage_append(ctx, "\r\n", 2);
}

void
chttp_connect(struct chttp_context *ctx, const char *host, size_t host_len, int port, int tls)
{
	chttp_context_ok(ctx);
	assert(host);
	assert(host_len);
	assert(port > 0);

	if (tls && !chttp_tls_enabled()) {
		chttp_error(ctx, CHTTP_ERR_TLS_INIT);
		return;
	}

	if (ctx->addr.state) {
		chttp_addr_ok(&ctx->addr);
		chttp_ABORT("invalid state, you can only connect once");
	}

	if (ctx->state == CHTTP_STATE_NONE) {
		assert_zero(ctx->data_start.dpage);
		chttp_dpage_append_mark(ctx, host, strlen(host) + 1, &ctx->hostname);
	} else if (ctx->state == CHTTP_STATE_INIT_HEADER) {
		if (!ctx->has_host && ctx->version > CHTTP_H_VERSION_1_0) {
			chttp_add_header(ctx, "Host", host);
			assert(ctx->has_host);
		}
	} else {
		// TODO explain better
		chttp_ABORT("invalid state, connection must be setup before sending");
	}

	chttp_dns_lookup(ctx, host, host_len, port, 0);

	if (ctx->error) {
		chttp_finish(ctx);
		return;
	}

	chttp_addr_resolved(&ctx->addr);

	if (tls) {
		ctx->addr.tls = 1;
	}
}

void
chttp_send(struct chttp_context *ctx)
{
	struct chttp_dpage *dpage;
	size_t offset;

	chttp_context_ok(ctx);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	if (ctx->addr.state != CHTTP_ADDR_RESOLVED) {
		chttp_ABORT("invalid state, connection must be setup before sending");
	}

	_finalize_request(ctx);

	chttp_addr_connect(ctx);

	if (ctx->error) {
		chttp_finish(ctx);
		return;
	}

	chttp_addr_connected(&ctx->addr);
	assert(ctx->data_start.dpage);

	offset = ctx->data_start.offset;

	for (dpage = ctx->data_start.dpage; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);
		assert(offset < dpage->offset);

		if (!dpage->offset) {
			continue;
		}

		chttp_tcp_send(&ctx->addr, dpage->data + offset, dpage->offset - offset);
		chttp_tcp_error_check(ctx);

		if (ctx->error) {
			return;
		}

		offset = 0;
	}

	ctx->state = CHTTP_STATE_SENT;
}

void
chttp_receive(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->state != CHTTP_STATE_SENT) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	ctx->state = CHTTP_STATE_RESP_HEADERS;

	chttp_dpage_reset_all(ctx);

	do {
		chttp_tcp_read(ctx);

		if (ctx->error) {
			return;
		} else if (ctx->state >= CHTTP_STATE_CLOSED) {
			chttp_error(ctx, CHTTP_ERR_NETWORK);
			return;
		}

		chttp_parse_response(ctx);

		if (ctx->error) {
			return;
		}
	} while (ctx->state == CHTTP_STATE_RESP_HEADERS);

	assert(ctx->state == CHTTP_STATE_RESP_BODY);
	chttp_dpage_ok(ctx->data_end.dpage);

	chttp_body_length(ctx, 1);

	if (ctx->error) {
		return;
	}

	chttp_addr_try_close(ctx);
}

void
chttp_error(struct chttp_context *ctx, enum chttp_error error)
{
	chttp_context_ok(ctx);
	assert(error > CHTTP_ERR_NONE);

	ctx->error = error;
	ctx->status = 0;

	chttp_finish(ctx);
}

void
chttp_finish(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->addr.state == CHTTP_ADDR_CONNECTED) {
		if (ctx->close || ctx->error || ctx->state < CHTTP_STATE_IDLE) {
			chttp_tcp_close(&ctx->addr);
		} else {
			chttp_tcp_pool_store(&ctx->addr);
		}
	}

	if (ctx->gzip_priv) {
		chttp_gzip_free(ctx->gzip_priv);
		ctx->gzip_priv = NULL;
	}

	chttp_dpage_reset_all(ctx);

	if (ctx->error) {
		ctx->state = CHTTP_STATE_DONE_ERROR;
	} else {
		ctx->state = CHTTP_STATE_DONE;
	}
}
