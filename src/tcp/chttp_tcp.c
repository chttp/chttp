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
	assert(ctx->addr.state != CHTTP_ADDR_CONNECTED);
	assert(sock >= 0);

	chttp_addr_init(&ctx->addr);

	ctx->addr.state = CHTTP_ADDR_CONNECTED;
	ctx->addr.sock = sock;

	chttp_caddr_connected(ctx);
}

int
chttp_addr_connect(struct chttp_addr *addr)
{
	int val;

	chttp_addr_ok(addr);
	assert(addr->state == CHTTP_ADDR_RESOLVED);

	addr->sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (addr->sock < 0) {
		return 1;
	}

	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val));

	val = connect(addr->sock, &addr->sa, addr->len);

	addr->state = CHTTP_ADDR_CONNECTED;

	// TODO non blocking timeout (EINPROGRESS)

	if (val) {
		return 1;
	}

	return 0;
}

void
chttp_tcp_connect(struct chttp_context *ctx)
{
	int ret;

	chttp_context_ok(ctx);
	chttp_caddr_ok(ctx);

	ret = chttp_addr_connect(&ctx->addr);

	if (ret) {
		if (ctx->addr.state == CHTTP_ADDR_CONNECTED) {
			chttp_tcp_close(ctx);
		}
		ctx->error = CHTTP_ERR_CONNECT;
	}
}

void
chttp_tcp_send(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	ssize_t ret;

	chttp_context_ok(ctx);
	chttp_caddr_connected(ctx);
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
	chttp_caddr_connected(ctx);
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
chttp_addr_close(struct chttp_addr *addr)
{
	chttp_addr_connected(addr);

	assert_zero(close(addr->sock));

	if (addr->len) {
		addr->state = CHTTP_ADDR_RESOLVED;
	} else  {
		addr->state = CHTTP_ADDR_NONE;
	}

	addr->sock = -1;
}

void
chttp_tcp_close(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_caddr_connected(ctx);
	assert(ctx->state < CHTTP_STATE_CLOSED);

	chttp_addr_close(&ctx->addr);
}
