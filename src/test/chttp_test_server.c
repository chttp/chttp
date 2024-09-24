/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#define _SERVER_IP_DEFAULT			"127.0.0.1"
#define _SERVER_JOIN_TIMEOUT_MS			2500
#define _SERVER_MAX_RANDOM_BODYLEN		(2 * 1024 * 1024)
#define _SERVER_MAX_RANDOM_CHUNKLEN		(32 * 1024)

struct _server_cmdentry {
	unsigned int				magic;
#define _SERVER_CMDENTRY			0xA50DBA3C

	TAILQ_ENTRY(_server_cmdentry)		entry;

	struct chttp_test_cmd			cmd;
};

struct chttp_test_server {
	unsigned int				magic;
#define _SERVER_MAGIC				0xF3969B6A

	struct chttp_test_context		*ctx;

	pthread_t				thread;

	pthread_mutex_t				cmd_lock;
	pthread_cond_t				cmd_signal;
	TAILQ_HEAD(, _server_cmdentry)		cmd_list;

	volatile int				stop;
	volatile int				started;
	volatile int				stopped;

	int					sock;
	int					port;
	int					http_sock;
	char					ip_str[128];
	char					port_str[16];

	struct chttp_context			*chttp;

	pthread_mutex_t				flush_lock;
	pthread_cond_t				flush_signal;
};

#define _server_ok(server)						\
	do {								\
		assert(server);						\
		assert((server)->magic == _SERVER_MAGIC);		\
	} while (0)

extern const char *_CHTTP_HEADER_FIRST;

static void *_server_thread(void *arg);

static inline struct chttp_test_server *
_server_context_ok(struct chttp_test_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->server, "server context does not exist");
	_server_ok(ctx->server);
	return ctx->server;
}

static inline void
_server_LOCK(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_mutex_lock(&server->cmd_lock));
}

static inline void
_server_UNLOCK(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_mutex_unlock(&server->cmd_lock));
}

static inline void
_server_SIGNAL(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_cond_signal(&server->cmd_signal));
}

static inline void
_server_WAIT(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_cond_wait(&server->cmd_signal, &server->cmd_lock));
}

static void
_server_cmdentry_free(struct _server_cmdentry *cmdentry)
{
	size_t i;

	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);

	free((char*)cmdentry->cmd.name);

	for (i = 0; i < cmdentry->cmd.param_count; i++) {
		free((char*)cmdentry->cmd.params[i].value);
	}

	chttp_ZERO(cmdentry);
	free(cmdentry);
}

static struct _server_cmdentry *
_server_cmdentry_alloc(void)
{
	struct _server_cmdentry *cmdentry;

	cmdentry = malloc(sizeof(*cmdentry));
	assert(cmdentry);

	chttp_ZERO(cmdentry);

	cmdentry->magic = _SERVER_CMDENTRY;

	return cmdentry;
}

static void
_server_cmd_async(struct chttp_test_server *server, struct chttp_test_cmd *cmd)
{
	struct _server_cmdentry *cmdentry;
	size_t i;

	_server_ok(server);
	assert(cmd);
	assert(cmd->func);
	assert_zero(cmd->async);

	cmdentry = _server_cmdentry_alloc();

	cmdentry->cmd.name = strdup(cmd->name);
	cmdentry->cmd.param_count = cmd->param_count;
	cmdentry->cmd.func = cmd->func;
	cmdentry->cmd.async = 1;

	for (i = 0; i < cmd->param_count; i++) {
		cmdentry->cmd.params[i].value = strdup(cmd->params[i].value);
		cmdentry->cmd.params[i].len = cmd->params[i].len;
		cmdentry->cmd.params[i].v_const = cmd->params[i].v_const;
	}

	_server_LOCK(server);

	TAILQ_INSERT_TAIL(&server->cmd_list, cmdentry, entry);

	_server_SIGNAL(server);
	_server_UNLOCK(server);
}

static void
_server_finish(struct chttp_test_context *ctx)
{
	struct chttp_test_server *server;
	struct _server_cmdentry *cmdentry, *temp;
	int ret;
	size_t finished = 0;

	server = _server_context_ok(ctx);

	_server_LOCK(server);

	assert(server->started);
	assert_zero(server->stop);
	assert_zero(server->stopped);
	server->stop = 1;

	_server_SIGNAL(server);
	_server_UNLOCK(server);

	ret = chttp_test_join_thread(server->thread, &server->stopped, _SERVER_JOIN_TIMEOUT_MS);
	chttp_test_ERROR(ret, "server thread is blocked");

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* thread joined");

	assert_zero(pthread_mutex_destroy(&server->cmd_lock));
	assert_zero(pthread_mutex_destroy(&server->flush_lock));
	assert_zero(pthread_cond_destroy(&server->cmd_signal));
	assert_zero(pthread_cond_destroy(&server->flush_signal));

	TAILQ_FOREACH_SAFE(cmdentry, &server->cmd_list, entry, temp) {
		assert(cmdentry->magic == _SERVER_CMDENTRY);

		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* unfinished cmd found %s",
			cmdentry->cmd.name);

		_server_cmdentry_free(cmdentry);

		finished++;
	}

	assert(TAILQ_EMPTY(&server->cmd_list));
	chttp_test_ERROR(finished, "all commands must be finished");

	if (server->chttp) {
		chttp_test_ERROR(server->chttp->error, "server error detected (%s)",
			chttp_error_msg(server->chttp));

		server->chttp->state = CHTTP_STATE_DONE;

		chttp_context_free(server->chttp);
		server->chttp = NULL;
	}

	if (server->sock >= 0) {
		assert_zero(close(server->sock));
	}
	if (server->http_sock >= 0) {
		assert_zero(close(server->http_sock));
	}

	chttp_ZERO(server);
	free(server);

	ctx->server = NULL;
}

static void
_server_init_socket(struct chttp_test_server *server)
{
	struct chttp_addr caddr;
	struct sockaddr_storage saddr;
	struct sockaddr *paddr;
	socklen_t len;
	int val;

	_server_ok(server);
	assert(server->sock == -1);

	val = chttp_dns_resolve(&caddr, server->ip_str, strlen(server->ip_str), 0, 0);
	chttp_test_ERROR(val, "server cannot resolve address %s", server->ip_str);
	assert(caddr.magic == CHTTP_ADDR_MAGIC);

	server->sock = socket(caddr.sa.sa_family, SOCK_STREAM, 0);
	assert(server->sock >= 0);

	val = 1;
	assert_zero(setsockopt(server->sock, SOL_SOCKET, SO_REUSEADDR,
		&val, sizeof(val)));

	assert_zero(bind(server->sock, &caddr.sa, caddr.len));
	assert_zero(listen(server->sock, 0));

	paddr = (struct sockaddr*)&saddr;
	len = sizeof(saddr);

	assert_zero(getsockname(server->sock, paddr, &len));
	assert(paddr->sa_family == caddr.sa.sa_family);

	switch (paddr->sa_family) {
		case AF_INET:
			server->port = ntohs(((struct sockaddr_in*)paddr)->sin_port);
			break;
		case AF_INET6:
			server->port = ntohs(((struct sockaddr_in6*)paddr)->sin6_port);
			break;
		default:
			chttp_test_ERROR(1, "Invalid server socket family");
	}

	assert(server->port >= 0);
	val = snprintf(server->port_str, sizeof(server->port_str), "%d", server->port);
	assert((size_t)val < sizeof(server->port_str));

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* socket port: %d",
		server->port);
}

void
chttp_test_cmd_server_init(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	assert(ctx);
	chttp_test_ERROR(cmd->param_count > 1, "too many parameters");
	chttp_test_ERROR(ctx->server != NULL, "server context exists");

	server = malloc(sizeof(*server));
	assert(server);

	chttp_ZERO(server);

	server->magic = _SERVER_MAGIC;
	server->ctx = ctx;
	server->sock = -1;
	server->port = -1;
	server->http_sock = -1;
	TAILQ_INIT(&server->cmd_list);
	assert_zero(pthread_mutex_init(&server->cmd_lock, NULL));
	assert_zero(pthread_mutex_init(&server->flush_lock, NULL));
	assert_zero(pthread_cond_init(&server->cmd_signal, NULL));
	assert_zero(pthread_cond_init(&server->flush_signal, NULL));

	if (cmd->param_count == 1) {
		snprintf(server->ip_str, sizeof(server->ip_str), "%s", cmd->params[0].value);
	} else {
		snprintf(server->ip_str, sizeof(server->ip_str), "%s", _SERVER_IP_DEFAULT);
	}
	chttp_test_ERROR_string(server->ip_str);

	_server_LOCK(server);

	// Start the server thread
	assert_zero(pthread_create(&server->thread, NULL, _server_thread, server));

	// Wait for it to ack
	assert_zero(server->started);
	_server_WAIT(server);
	assert(server->started);

	_server_UNLOCK(server);

	_server_init_socket(server);

	// TODO tls support

	ctx->server = server;

	chttp_test_register_finish(ctx, "server", _server_finish);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "*SERVER* init completed");
}

void
chttp_test_cmd_server_accept(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	struct sockaddr_storage saddr;
	struct sockaddr *addr;
	socklen_t len;
	char remote[128] = {0};
	int remote_port = -1;

	server = _server_context_ok(ctx);
	assert(server->sock >= 0);
	assert(server->port >= 0);
	chttp_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	assert(server->http_sock == -1);

	addr = (struct sockaddr*)&saddr;
	len = sizeof(saddr);

	server->http_sock = accept(server->sock, addr, &len);
	assert(server->http_sock >= 0);

	chttp_sa_string(addr, remote, sizeof(remote), &remote_port);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* remote client %s:%d",
		remote, remote_port);
}

void
chttp_test_cmd_server_close(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	assert(server->http_sock >= 0);

	assert_zero(close(server->http_sock));

	server->http_sock = -1;
}

char *
chttp_test_var_server_host(struct chttp_test_context *ctx)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	assert(server->sock >= 0);
	chttp_test_ERROR_string(server->ip_str);

	return server->ip_str;
}

char *
chttp_test_var_server_port(struct chttp_test_context *ctx)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	assert(server->port >= 0);

	return server->port_str;
}

static void
_server_parse_request_url(struct chttp_context *ctx, size_t start, size_t end)
{
	struct chttp_dpage *dpage;
	size_t len, count, i;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->dpage_last);
	assert_zero(ctx->seen_first);

	dpage = ctx->dpage_last;
	len = end - start;

	// TODO remove
	assert(strlen((char*)&dpage->data[start]) == len);

	for (i = start, count = 0; i < end; i++) {
		if (dpage->data[i] < ' ') {
			chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
			return;
		} else if (dpage->data[i] == ' ') {
			dpage->data[i] = '\0';
			count++;

			if (dpage->data[i + 1] <= ' ') {
				chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
				return;
			}
		}
	}

	if (count != 2) {
		chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
		return;
	}
}

void
chttp_test_cmd_server_read_request(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	struct chttp_test *test;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);
	test = chttp_test_convert(server->ctx);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	assert(server->http_sock >= 0);

	if (server->chttp) {
		chttp_test_ERROR(server->chttp->error, "server error detected (%s)",
			chttp_error_msg(server->chttp));

		server->chttp->state = CHTTP_STATE_DONE;
		chttp_context_free(server->chttp);
		server->chttp = NULL;
	}

	server->chttp = malloc(sizeof(struct chttp_context));
	assert(server->chttp);
	chttp_context_init_buf(server->chttp, sizeof(struct chttp_context));

	server->chttp->free = 1;
	server->chttp->state = CHTTP_STATE_RESP_HEADERS;

	chttp_tcp_import(server->chttp, server->http_sock);

	do {
		chttp_tcp_read(server->chttp);
		chttp_test_ERROR(server->chttp->state >= CHTTP_STATE_CLOSED,
			"server read network error");

		chttp_parse_headers(server->chttp, &_server_parse_request_url);
		chttp_test_ERROR(server->chttp->error, "*SERVER* %s",
			chttp_error_msg(server->chttp));
	} while (server->chttp->state == CHTTP_STATE_RESP_HEADERS);

	assert_zero(server->chttp->error);
	assert(server->chttp->state == CHTTP_STATE_RESP_BODY);

	chttp_body_length(server->chttp, 0);
	chttp_test_ERROR(server->chttp->length, "*SERVER* request bodies not supported");

	assert(server->chttp->state == CHTTP_STATE_IDLE);

	if (test->verbocity == CHTTP_LOG_VERY_VERBOSE) {
		chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* dpage dump");
		chttp_dpage_debug(server->chttp->dpage);
	}

	server->http_sock = server->chttp->addr.sock;

	chttp_addr_reset(&server->chttp->addr);
}

static void
_server_match_header(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	const char *header, *header_value, *expected, *dup;
	size_t len;
	int sub = 0;

	server = _server_context_ok(ctx);
	chttp_context_ok(server->chttp);
	assert(cmd);
	assert(cmd->name);
	assert(cmd->async);

	header = header_value = expected = NULL;

	if (!strcmp(cmd->name, "server_method_match")) {
		assert(cmd->param_count == 1);

		header = "_METHOD";
		expected = cmd->params[0].value;
		header_value = chttp_get_header(server->chttp, _CHTTP_HEADER_FIRST);
		dup = NULL;
	} else if (!strcmp(cmd->name, "server_url_match")) {
		assert(cmd->param_count == 1);

		header = "_URL";
		expected = cmd->params[0].value;

		header_value = chttp_get_header(server->chttp, _CHTTP_HEADER_FIRST);
		assert(header_value);
		len = strlen(header_value);
		header_value += len + 1;
		dup = NULL;
	} else if (!strcmp(cmd->name, "server_version_match")) {
		assert(cmd->param_count == 1);

		header = "_VERSION";
		expected = cmd->params[0].value;

		header_value = chttp_get_header(server->chttp, _CHTTP_HEADER_FIRST);
		assert(header_value);
		len = strlen(header_value);
		header_value += len + 1;
		len = strlen(header_value);
		header_value += len + 1;
		dup = NULL;
	} else if (!strcmp(cmd->name, "server_header_match")) {
		assert(cmd->param_count == 2);

		header = cmd->params[0].value;
		expected = cmd->params[1].value;
		header_value = chttp_get_header(server->chttp, header);
		dup = chttp_get_header_pos(server->chttp, header, 1);
	} else if (!strcmp(cmd->name, "server_header_submatch")) {
		assert(cmd->param_count == 2);

		header = cmd->params[0].value;
		expected = cmd->params[1].value;
		header_value = chttp_get_header(server->chttp, header);
		dup = chttp_get_header_pos(server->chttp, header, 1);
		sub = 1;
	} else if (!strcmp(cmd->name, "server_header_exists")) {
		assert(cmd->param_count == 1);

		header = cmd->params[0].value;
		expected = NULL;
		header_value = chttp_get_header(server->chttp, header);
		dup = chttp_get_header_pos(server->chttp, header, 1);
	} else if (!strcmp(cmd->name, "server_header_not_exists")) {
		assert(cmd->param_count == 1);

		header = cmd->params[0].value;
		header_value = chttp_get_header(server->chttp, header);

		chttp_test_ERROR(header_value != NULL, "header %s exists", header);

		chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* header not exists %s",
			header);

		return;
	}else {
		assert_zero("INVALID SERVER MATCH");
	}

	chttp_test_ERROR(!header_value, "header %s not found", header);
	chttp_test_ERROR(dup != NULL, "duplicate %s header found", header);

	if (!expected) {
		chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* header exists %s",
			header);
		return;
	}

	if (sub) {
		chttp_test_ERROR(!strstr(header_value, expected), "value %s not found in header "
			"%s:%s", expected, header, header_value);
	} else {
		chttp_test_ERROR(strcmp(header_value, expected), "headers dont match, found %s:%s, "
			"expected %s", header, header_value, expected);
	}

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* headers match %s:%s%s%s%s",
		header, header_value, sub ? " (" : "", sub ? expected : "", sub ? ")" : "");
}

void
chttp_test_cmd_server_method_match(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_url_match(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_version_match(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_match(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_submatch(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_exists(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_not_exists(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
_server_send_buf(struct chttp_test_server *server, const uint8_t *buf, size_t len)
{
	ssize_t ret;

	_server_ok(server);
	assert(server->http_sock >= 0);

	ret = send(server->http_sock, buf, len, MSG_NOSIGNAL);
	assert(ret > 0 && (size_t)ret == len);
}
void __chttp_attr_printf
_server_send_printf(struct chttp_test_server *server, const char *fmt, ...)
{
	va_list ap;
	char buf[256];
	size_t len;

	_server_ok(server);

	va_start(ap, fmt);

	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	assert(len < sizeof(buf));

	_server_send_buf(server, (uint8_t*)buf, len);

	va_end(ap);
}

static void
_server_send_response(struct chttp_test_server *server, struct chttp_test_cmd *cmd,
    int H1_1, int partial)
{
	long status;
	char *reason, *body = "";
	ssize_t ret;
	size_t body_len = 0;

	_server_ok(server);
	assert(server->http_sock >= 0);
	assert(cmd);
	assert(cmd->param_count <= 3);

	status = 200;
	reason = "OK";

	if (cmd->param_count >= 1) {
		status = chttp_test_parse_long(cmd->params[0].value);
		assert(status > 0 && status < 1000);
	}
	if (cmd->param_count >= 2) {
		reason = cmd->params[1].value;
	}
	if (cmd->param_count == 3) {
		assert_zero(partial);
		body = cmd->params[2].value;
		body_len = cmd->params[2].len;
	}

	_server_send_printf(server, "HTTP/1.%c %ld %s\r\n", H1_1 ? '1' : '0', status, reason);
	_server_send_printf(server, "Server: chttp_test %s\r\n", CHTTP_VERSION);
	_server_send_printf(server, "Date: // TODO\r\n");

	if (partial) {
		return;
	}

	if (H1_1) {
		_server_send_printf(server, "Content-Length: %zu\r\n\r\n", body_len);
	} else {
		_server_send_printf(server, "\r\n");
	}

	if (body_len > 0) {
		ret = send(server->http_sock, body, body_len, MSG_NOSIGNAL);
		assert(ret > 0 && (size_t)ret == body_len);
	}

	if (!H1_1) {
		assert_zero(close(server->http_sock));
		server->http_sock = -1;
	}
}

void
chttp_test_cmd_server_send_response(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	long status;

	server = _server_context_ok(ctx);
	assert(cmd);
	chttp_test_ERROR(cmd->param_count > 3, "too many parameters");

	if (cmd->param_count >= 1) {
		status = chttp_test_parse_long(cmd->params[0].value);
		chttp_test_ERROR(status <= 0 || status > 999, "invalid status code");
	}
	if (cmd->param_count >= 2) {
		chttp_test_ERROR_string(cmd->params[1].value);
	}

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_response(server, cmd, 1, 0);
}

void
chttp_test_cmd_server_send_response_H1_0(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	long status;

	server = _server_context_ok(ctx);
	assert(cmd);
	chttp_test_ERROR(cmd->param_count > 3, "too many parameters");

	if (cmd->param_count >= 1) {
		status = chttp_test_parse_long(cmd->params[0].value);
		chttp_test_ERROR(status <= 0 || status > 999, "invalid status code");
	}
	if (cmd->param_count >= 2) {
		chttp_test_ERROR_string(cmd->params[1].value);
	}

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_response(server, cmd, 0, 0);
}

void
chttp_test_cmd_server_send_response_partial(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	long status;

	server = _server_context_ok(ctx);
	assert(cmd);
	chttp_test_ERROR(cmd->param_count > 2, "too many parameters");

	if (cmd->param_count >= 1) {
		status = chttp_test_parse_long(cmd->params[0].value);
		chttp_test_ERROR(status <= 0 || status > 999, "invalid status code");
	}
	if (cmd->param_count == 2) {
		chttp_test_ERROR_string(cmd->params[1].value);
	}

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_response(server, cmd, 1, 1);
}

void
chttp_test_cmd_server_send_header(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_printf(server, "%s\r\n", cmd->params[0].value);
}

void
chttp_test_cmd_server_send_header_done(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_printf(server, "\r\n");
}

void
chttp_test_cmd_server_start_chunked(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_printf(server, "Transfer-Encoding: chunked\r\n\r\n");
}

void
chttp_test_cmd_server_send_chunked(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_test_unescape(&cmd->params[0]);

	_server_send_printf(server, "%x\r\n%s\r\n", (unsigned int)cmd->params[0].len,
		cmd->params[0].value);
}

void
chttp_test_cmd_server_end_chunked(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_printf(server, "0\r\n\r\n");
}

void
chttp_test_cmd_server_send_raw(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_test_unescape(&cmd->params[0]);

	_server_send_buf(server, (uint8_t*)cmd->params[0].value, cmd->params[0].len);
}

void
chttp_test_cmd_server_send_random_body(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	struct chttp_test_md5 md5;
	long bodylen, chunklen;
	size_t sent, send_size, partial, len;
	size_t chunks, subchunks;
	uint8_t buf[8192];

	server = _server_context_ok(ctx);
	chttp_test_ERROR(cmd->param_count > 2, "Too many params");

	bodylen = -1;
	chunklen = -1;

	if (cmd->param_count > 0) {
		bodylen = chttp_test_parse_long(cmd->params[0].value);
	}
	if (cmd->param_count > 1) {
		chunklen = chttp_test_parse_long(cmd->params[1].value);
	}

	chttp_test_random_seed();
	chttp_test_md5_init(&md5);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	if (bodylen < 0) {
		bodylen = chttp_test_random(0, _SERVER_MAX_RANDOM_BODYLEN);
	}

	if (chunklen) {
		_server_send_printf(server, "Transfer-Encoding: chunked\r\n\r\n");
	} else {
		_server_send_printf(server, "Content-Length: %zd\r\n\r\n", bodylen);
	}

	sent = 0;
	chunks = subchunks = 0;
	assert(bodylen >= 0);

	while (sent < (size_t)bodylen) {
		if (chunklen < 0) {
			send_size = chttp_test_random(1, _SERVER_MAX_RANDOM_CHUNKLEN);
		} else if (chunklen == 0) {
			send_size = bodylen;
		} else {
			send_size = chunklen;
		}

		if (send_size > bodylen - sent) {
			send_size = bodylen - sent;
		}

		if (chunklen) {
			_server_send_printf(server, "%x\r\n", (unsigned int)send_size);
		}

		partial = 0;

		while (partial < send_size) {
			len = send_size - partial;
			if (len > sizeof(buf)) {
				len = sizeof(buf);
			}

			chttp_test_fill_random(buf, len);

			_server_send_buf(server, buf, len);

			chttp_test_md5_update(&md5, buf, len);

			partial += len;
			subchunks++;
		}

		assert(partial == send_size);
		sent += partial;

		chunks++;

		if (chunklen) {
			_server_send_printf(server, "\r\n");
		}
	}

	assert(sent == (size_t)bodylen);

	if (chunklen) {
		_server_send_printf(server, "0\r\n\r\n");
	}

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* sent random body bytes %zu "
		"(%zu %zu)", sent, chunks, subchunks);

	chttp_test_md5_final(&md5);
	chttp_test_md5_store_server(ctx, &md5);

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* body md5 %s", ctx->md5_server);
}

void
chttp_test_cmd_server_sleep_ms(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	long ms;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	ms = chttp_test_parse_long(cmd->params[0].value);
	chttp_test_ERROR(ms < 0, "invalid sleep time");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_test_sleep_ms(ms);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "*SERVER* slept %ldms", ms);
}

void
chttp_test_cmd_server_flush_async(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (cmd->async) {
		assert_zero(pthread_mutex_lock(&server->flush_lock));

		assert_zero(pthread_cond_signal(&server->flush_signal));
		chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* flush signal sent");

		assert_zero(pthread_mutex_unlock(&server->flush_lock));

		return;
	}

	assert_zero(pthread_mutex_lock(&server->flush_lock));

	_server_cmd_async(server, cmd);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "*SERVER* waiting for flush...");

	assert_zero(pthread_cond_wait(&server->flush_signal, &server->flush_lock));

	assert_zero(pthread_mutex_unlock(&server->flush_lock));

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "*SERVER* flushed");
}

static void
_server_cmd(struct chttp_test_server *server, struct _server_cmdentry *cmdentry)
{
	_server_ok(server);
	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);
	assert(cmdentry->cmd.async);
	assert(cmdentry->cmd.func);

	cmdentry->cmd.func(server->ctx, &cmdentry->cmd);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* thread cmd %s completed",
		cmdentry->cmd.name);
}

static void *
_server_thread(void *arg)
{
	struct chttp_test_server *server = arg;
	struct _server_cmdentry *cmdentry;

	_server_ok(server);

	_server_LOCK(server);

	// Ack the server init
	server->started = 1;
	_server_SIGNAL(server);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* thread started");

	while (!server->stop) {
		if (TAILQ_EMPTY(&server->cmd_list)) {
			_server_WAIT(server);
			continue;
		}

		// Grab work
		assert(!TAILQ_EMPTY(&server->cmd_list));
		cmdentry = TAILQ_FIRST(&server->cmd_list);
		assert(cmdentry);
		assert(cmdentry->magic == _SERVER_CMDENTRY);
		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		_server_UNLOCK(server);

		_server_cmd(server, cmdentry);
		_server_cmdentry_free(cmdentry);

		_server_LOCK(server);
	}

	assert_zero(server->stopped);
	server->stopped = 1;

	_server_UNLOCK(server);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "*SERVER* thread finished");

	return NULL;
}
