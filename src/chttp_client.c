/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>

int
main(int argc, char **argv) {
	struct chttp_context *context, scontext;
	char ctx_buf[2000], ctx_buf2[CHTTP_CTX_SIZE + 1];

	printf("chttp client %s\n", CHTTP_VERSION);

	printf("sizeof(struct chttp_ctx)=%zu\n", CHTTP_CTX_SIZE);
	printf("sizeof(struct chttp_dpage)=%zu\n", sizeof(struct chttp_dpage));

	//_DEBUG_CHTTP_DPAGE_MIN_SIZE = 12;

	// dynamic
	context = chttp_context_alloc();

	chttp_set_version(context, CHTTP_H_VERSION_1_1);
	chttp_set_method(context, "GET");
	chttp_set_url(context, "/abc");
	chttp_add_header(context, "header1", "abc123");
	chttp_add_header(context, "header1", "duplicate");
	chttp_add_header(context, "header2", "XYZZZZ");
	chttp_add_header(context, "header1", "again, why");
	chttp_add_header(context, "header3", "very, imortant; information");

	chttp_context_debug(context);

	chttp_delete_header(context, "header1");
	chttp_delete_header(context, "header2");

	chttp_context_debug(context);

	chttp_send(context, "ec2.rezsoft.org", 80, 0);

	chttp_recv(context);

	chttp_context_debug(context);

	printf("XXX server: '%s'\n", chttp_get_header(context, "server"));
	printf("XXX date: '%s'\n", chttp_get_header(context, "DATE"));
	printf("XXX _reason: '%s'\n", chttp_get_header(context, CHTTP_HEADER_REASON));
	printf("XXX content-type: '%s'\n", chttp_get_header(context, "content-type"));
	printf("XXX content-length: '%s'\n", chttp_get_header(context, "content-length"));
	printf("XXX content-encoding: '%s'\n", chttp_get_header(context,
	    "content-encoding"));
	printf("XXX transfer-encoding: '%s'\n", chttp_get_header(context,
	    "transfer-encoding"));
	printf("XXX abc: '%s'\n", chttp_get_header(context, "abc"));

	chttp_context_free(context);

	// static
	chttp_context_init(&scontext);
	chttp_set_url(&scontext, "/");
	chttp_add_header(&scontext, "a", "1");
	chttp_add_header(&scontext, "a", "1");
	chttp_context_debug(&scontext);
	chttp_delete_header(&scontext, "x");
	chttp_delete_header(&scontext, "a");
	chttp_add_header(&scontext, "x", "2");
	chttp_context_debug(&scontext);
	chttp_send(&scontext, "textglass.org", 80, 0);
	chttp_recv(&scontext);
	printf("XXX server: '%s'\n", chttp_get_header(&scontext, "server"));
	printf("XXX date: '%s'\n", chttp_get_header(&scontext, "DATE"));
	printf("XXX _reason: '%s'\n", chttp_get_header(&scontext, CHTTP_HEADER_REASON));
	printf("XXX content-type: '%s'\n", chttp_get_header(&scontext, "content-type"));
	printf("XXX content-length: '%s'\n", chttp_get_header(&scontext, "content-length"));
	printf("XXX content-encoding: '%s'\n", chttp_get_header(&scontext,
	    "content-encoding"));
	printf("XXX transfer-encoding: '%s'\n", chttp_get_header(&scontext,
	    "transfer-encoding"));
	printf("XXX abc: '%s'\n", chttp_get_header(&scontext, "abc"));
	chttp_context_debug(&scontext);
	chttp_context_free(&scontext);

	// custom
	context = chttp_context_init_buf(ctx_buf, sizeof(ctx_buf));
	chttp_set_url(context, "/123-custom");
	chttp_context_debug(context);
	chttp_context_free(context);

	// custom2
	context = chttp_context_init_buf(ctx_buf2, sizeof(ctx_buf2));
	chttp_set_url(context, "/123-nodpage");
	chttp_context_debug(context);
	chttp_context_free(context);

	return (0);
}
