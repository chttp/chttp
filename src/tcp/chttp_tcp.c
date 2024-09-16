/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

static void
_tcp_set_nonblocking(struct chttp_addr *addr)
{
	int val, ret;

	chttp_addr_connected(addr);

	val = 1;
	ret = ioctl(addr->sock, FIONBIO, &val);
	assert_zero(ret);

	addr->nonblocking = 1;
}

static void
_tcp_set_blocking(struct chttp_addr *addr)
{
	int val, ret;

	chttp_addr_connected(addr);

	val = 0;
	ret = ioctl(addr->sock, FIONBIO, &val);
	assert_zero(ret);

	addr->nonblocking = 0;
}

static void
_tcp_poll(struct chttp_addr *addr, short events, int timeout_msec)
{
	struct pollfd fds[1];

	chttp_addr_connected(addr);
	assert(addr->nonblocking);
	assert(timeout_msec > 0);

	fds[0].fd = addr->sock;
	fds[0].events = events;
	fds[0].revents = 0;

	addr->poll_result = poll(fds, 1, timeout_msec);
	addr->poll_revents = fds[0].revents;
}

static int
_tcp_poll_connected(struct chttp_addr *addr)
{
	int error, ret;
	socklen_t error_len;

	_tcp_poll(addr, POLLWRNORM, addr->timeout_connect_ms);

	if (addr->poll_result <= 0) {
		return 0;
	}

	if (!(addr->poll_revents & POLLWRNORM)) {
		return 0;
	}

	chttp_addr_connected(addr);

	error_len = sizeof(error);

	ret = getsockopt(addr->sock, SOL_SOCKET, SO_ERROR, &error, &error_len);
	assert_zero(ret);

	if (error) {
		return 0;
	}

	return 1;
}

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
	int val, ret;
	struct timeval timeout;

	chttp_addr_resolved(addr);

	addr->sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (addr->sock < 0) {
		return 1;
	}

	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	val = 1;
	setsockopt(addr->sock, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val));

	addr->state = CHTTP_ADDR_CONNECTED;
	addr->time_start = chttp_get_time();

	if (addr->timeout_connect_ms > 0) {
		_tcp_set_nonblocking(addr);
	}

	val = connect(addr->sock, &addr->sa, addr->len);

	if (val && errno == EINPROGRESS && addr->nonblocking) {
		ret = _tcp_poll_connected(addr);

		if (ret <= 0) {
			return 1;
		}
	} else if (val) {
		return 1;
	}

	if (addr->nonblocking) {
		_tcp_set_blocking(addr);
	}

	assert_zero(addr->nonblocking);

	if (addr->timeout_transfer_ms > 0) {
		timeout.tv_sec = addr->timeout_transfer_ms / 1000;
		timeout.tv_usec = (addr->timeout_transfer_ms % 1000) * 1000;

		ret = setsockopt(addr->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
			sizeof(timeout));
		(void)ret; // Ignored
		// TODO send timeout
	}

	return 0;
}

void
chttp_tcp_connect(struct chttp_context *ctx)
{
	int ret;

	chttp_context_ok(ctx);
	chttp_addr_ok(&ctx->addr);

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
	assert_zero(ctx->addr.nonblocking);
	assert(buf);
	assert(buf_len);

	if (ctx->tls) {
		chttp_tls_write(ctx, buf, buf_len);
		return;
	}

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
	size_t bytes;
	int error;

	chttp_context_ok(ctx);
	chttp_caddr_connected(ctx);
	assert_zero(ctx->addr.nonblocking);
	assert(buf);
	assert(buf_len);

	if (ctx->tls) {
		bytes = chttp_tls_read(ctx, buf, buf_len, &error);
		ret = (ssize_t)bytes;

		if (error) {
			ret = -1;
		} else {
			assert(ret >= 0);
		}
	} else {
		ret = recv(ctx->addr.sock, buf, buf_len, 0);
	}

	if (ret == 0) {
		chttp_tcp_close(ctx);
		ctx->state = CHTTP_STATE_CLOSED;
		return 0;

	} else if (ret < 0) {
		chttp_error(ctx, CHTTP_ERR_NETWORK);
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
