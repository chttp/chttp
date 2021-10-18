/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
	struct chttp_context *context, scontext;
	char ctx_buf[2000], ctx_buf2[CHTTP_CTX_SIZE + 1];
	char body_buf[100];
	size_t body_len;

	(void)argc;
	(void)argv;

	printf("chttp_client %s\n", CHTTP_VERSION);

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
	chttp_connect(context, "ec2.rezsoft.org", strlen("ec2.rezsoft.org"), 80, 0);
	chttp_send(context);
	chttp_context_debug(context);
	chttp_receive(context);
	chttp_context_debug(context);
	do {
		body_len = chttp_get_body(context, body_buf, sizeof(body_buf));
		printf("***BODY*** (%zu, %d)\n", body_len, context->state);
		chttp_print_hex(body_buf, body_len);
	} while (body_len && context->state == CHTTP_STATE_RESP_BODY);
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
	chttp_connect(&scontext, "textglass.org", strlen("textglass.org"), 80, 0);
	chttp_send(context);
	chttp_context_debug(&scontext);
	chttp_receive(&scontext);
	chttp_context_debug(&scontext);
	do {
		body_len = chttp_get_body(&scontext, body_buf, sizeof(body_buf));
		printf("***BODY*** (%zu, %d)\n", body_len, scontext.state);
		chttp_print_hex(body_buf, body_len);
	} while (body_len && scontext.state == CHTTP_STATE_RESP_BODY);
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
