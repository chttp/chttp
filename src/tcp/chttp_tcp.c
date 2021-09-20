/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

/*
static void
_tcp_set_nonblocking(int sock)
{
	int val, ret;

	val = 1;
	ret = ioctl(sock, FIONBIO, &val);
	(void)ret;
}

static void
_tcp_set_blocking(int sock)
{
	int val, ret;

	val = 0;
	ret = ioctl(sock, FIONBIO, &val);
	(void)ret;
}
*/

void
chttp_tcp_import(struct chttp_context *ctx, int sock)
{
	chttp_context_ok(ctx);
	assert_zero(ctx->addr.magic);
	assert_zero(ctx->addr.len);
	assert_zero(ctx->addr.sa.sa_family);
	assert(sock >= 0);

	ctx->addr.magic = CHTTP_ADDR_MAGIC;
	ctx->addr.state = CHTTP_ADDR_CONNECTED;
	ctx->addr.sock = sock;

	chttp_addr_connected(ctx);
}

void
chttp_tcp_connect(struct chttp_context *ctx)
{
	struct chttp_addr *addr;
	int val;

	chttp_context_ok(ctx);
	chttp_addr_ok(ctx);
	assert(ctx->addr.state == CHTTP_ADDR_RESOLVED);

	addr = &ctx->addr;

	addr->sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (addr->sock < 0) {
		ctx->error = CHTTP_ERR_CONNECT;
		return;
	}

	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val));

	val = connect(addr->sock, &addr->sa, addr->len);

	addr->state = CHTTP_ADDR_CONNECTED;

	// TODO non blocking timeout (EINPROGRESS)

	if (val) {
		chttp_tcp_close(ctx);
		ctx->error = CHTTP_ERR_CONNECT;

		return;
	}

	return;
}

void
chttp_tcp_send(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	ssize_t ret;

	chttp_context_ok(ctx);
	chttp_addr_connected(ctx);
	assert(buf);
	assert(buf_len);

	ret = send(ctx->addr.sock, buf, buf_len, MSG_NOSIGNAL);
	assert(ret > 0 && (size_t)ret == buf_len); // TODO implement partial send
}

void
chttp_tcp_read(struct chttp_context *ctx)
{
	size_t ret;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->dpage_last);
	assert(ctx->dpage_last->offset < ctx->dpage_last->length);

	ret = chttp_tcp_read_buf(ctx, ctx->dpage_last->data + ctx->dpage_last->offset,
		ctx->dpage_last->length - ctx->dpage_last->offset);

	ctx->dpage_last->offset += ret;
	assert(ctx->dpage_last->offset <= ctx->dpage_last->length);
}

size_t
chttp_tcp_read_buf(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	ssize_t ret;

	chttp_context_ok(ctx);
	chttp_addr_connected(ctx);
	assert(buf);
	assert(buf_len);

	ret = recv(ctx->addr.sock, buf, buf_len, 0);

	if (ret == 0) {
		chttp_tcp_close(ctx);
		ctx->state = CHTTP_STATE_CLOSED;
		return 0;

	} else if (ret < 0) {
		chttp_error(ctx, CHTTP_ERR_NETOWRK);
		return 0;
	}

	return ret;
}

void
chttp_tcp_close(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_addr_connected(ctx);
	assert(ctx->state < CHTTP_STATE_CLOSED);

	assert_zero(close(ctx->addr.sock));

	if (ctx->addr.len) {
		ctx->addr.state = CHTTP_ADDR_RESOLVED;
	} else  {
		ctx->addr.state = CHTTP_ADDR_NONE;
	}

	ctx->addr.sock = -1;
}
