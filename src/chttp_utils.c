/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void
chttp_context_debug(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	printf("chttp_ctx state=%d error=%d (%s) version=%d data_last=%p\n"
		"\tdata_start=%p:%zu:%zu data_end=%p:%zu:%zu\n"
		"\thostname=%p:%zu:%zu\n"
		"\tstatus=%d length=%ld free=%u has_host=%u close=%u chunked=%u tls=%d\n"
		"\ttime=%lf\n",
		ctx->state, ctx->error, chttp_error_msg(ctx), ctx->version, (void*)ctx->dpage_last,
		(void*)ctx->data_start.dpage, ctx->data_start.offset, ctx->data_start.length,
		(void*)ctx->data_end.dpage, ctx->data_end.offset, ctx->data_end.length,
		(void*)ctx->hostname.dpage, ctx->hostname.offset, ctx->hostname.length,
		ctx->status, ctx->length, ctx->free, ctx->has_host, ctx->close, ctx->chunked, ctx->addr.tls,
		chttp_get_time() - ctx->addr.time_start);

	chttp_dpage_debug(ctx->dpage);
}

void
chttp_dpage_debug(struct chttp_dpage *dpage)
{
	while (dpage) {
		chttp_dpage_ok(dpage);

		printf("\tchttp_dpage free=%u length=%zu offset=%zu ptr=%p (%p)\n",
			dpage->free, dpage->length, dpage->offset, (void*)dpage, (void*)dpage->data);

		if (dpage->offset) {
			chttp_print_hex(dpage->data, dpage->offset);
		}

		dpage = dpage->next;
	}
}

void
chttp_print_hex(void *buf, size_t buf_len)
{
	uint8_t *buffer;
	size_t i;

	assert(buf);

	buffer = buf;

	printf("\t> ");

	for (i = 0; i < buf_len; i++) {
		if (buffer[i] >= ' ' && buffer[i] <= '~') {
			printf("%c", buffer[i]);
			continue;
		}

		switch(buffer[i]) {
			case '\r':
				printf("\\r");
				break;
			case '\n':
				if (i == buf_len - 1) {
					printf("\\n");
				} else {
					printf("\\n\n\t> ");
				}
				break;
			case '\\':
				printf("\\\\");
				break;
			default:
				printf("\\0x%x", buffer[i]);
		}
	}

	printf("\n");
}

size_t
chttp_safe_add(size_t *dest, size_t value)
{
	assert(dest);

        return __sync_add_and_fetch(dest, value);
}

void
chttp_do_abort(const char *function, const char *file, int line, const char *reason)
{
	(void)file;
	(void)line;

	fprintf(stderr, "%s(): %s\n", function, reason);
	abort();
}

const char *
chttp_error_msg(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	switch (ctx->error) {
		case CHTTP_ERR_NONE:
			return "none";
		case CHTTP_ERR_INIT:
			return "initialization";
		case CHTTP_ERR_DNS:
			return "DNS error";
		case CHTTP_ERR_CONNECT:
			return "cannot make connection";
		case CHTTP_ERR_NETWORK:
			return "network error";
		case CHTTP_ERR_RESP_PARSE:
			return "cannot parse response";
		case CHTTP_ERR_RESP_LENGTH:
			return "cannot parse response body length";
		case CHTTP_ERR_RESP_CHUNK:
			return "cannot parse response body chunk";
		case CHTTP_ERR_RESP_BODY:
			return "cannot parse response body";
		case CHTTP_ERR_TLS_INIT:
			return "TLS initialization error";
		case CHTTP_ERR_TLS_HANDSHAKE:
			return "TLS handshake error";
	}

	return "unknown";
}

void
chttp_sa_string(struct sockaddr *sa, char *buf, size_t buf_len, int *port)
{
	assert(sa);

	buf[0] = '\0';
	*port = -1;

	switch (sa->sa_family) {
		case AF_INET:
			assert(inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr),
				buf, buf_len));
			*port = ntohs(((struct sockaddr_in*)sa)->sin_port);
			break;
		case AF_INET6:
			assert(inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr),
				buf, buf_len));
			*port = ntohs(((struct sockaddr_in6*)sa)->sin6_port);
			break;
		default:
			chttp_ABORT("Invalid sockaddr family");
	}
}

double
chttp_get_time(void)
{
	struct timespec ts;

        assert_zero(clock_gettime(CLOCK_REALTIME, &ts));

        return ts.tv_sec + ((double)ts.tv_nsec / (1000 * 1000 * 1000));
}