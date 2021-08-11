/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

void
_tcp_set_nonblocking(int sock)
{
	int val, ret;

	val = 1;
	ret = ioctl(sock, FIONBIO, &val);
	(void)ret;
}

void
_tcp_set_blocking(int sock)
{
	int val, ret;

	val = 0;
	ret = ioctl(sock, FIONBIO, &val);
	(void)ret;
}

void
chttp_tcp_connect(struct chttp_context *ctx)
{
	struct chttp_addr *addr;
	int val;

	chttp_context_ok(ctx);

	addr = &ctx->addr;

	assert(addr->magic == CHTTP_ADDR_MAGIC);
	assert(addr->sock == -1);

	addr->sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (addr->sock < 0) {
		ctx->error = CHTTP_ERR_CONNECT;
		return;
	}

	ctx->state = CHTTP_STATE_CONNECTING;

	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val));

	val = connect(addr->sock, &addr->sa, addr->len);

	// TODO non blocking timeout (EINPROGRESS)

	if (val) {
		chttp_tcp_close(ctx);
		ctx->error = CHTTP_ERR_CONNECT;

		return;
	}

	ctx->state = CHTTP_STATE_CONNECTED;

	return;
}

void
chttp_tcp_read(struct chttp_context *ctx)
{
	int ret;

	chttp_context_ok(ctx);
	chttp_addr_ok(ctx);

	chttp_dpage_ok(ctx->data_last);
	assert(ctx->data_last->offset < ctx->data_last->length);

	ret = recv(ctx->addr.sock, ctx->data_last->data + ctx->data_last->offset,
		ctx->data_last->length - ctx->data_last->offset, 0);

	if (ret <= 0) {
		// TODO other errors
		chttp_finish(ctx);

		return;
	}

	ctx->data_last->offset += ret;
	assert(ctx->data_last->offset <= ctx->data_last->length);
}

void
chttp_tcp_close(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_addr_ok(ctx);
	assert(ctx->addr.sock >= 0);

	assert_zero(close(ctx->addr.sock));

	ctx->addr.sock = -1;
}
