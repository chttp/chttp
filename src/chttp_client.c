/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>

int
main(int argc, char **argv) {
	struct chttp_context *context, scontext;
	char ctx_buf[2000];

	printf("chttp client %s\n", CHTTP_VERSION);

	printf("sizeof(struct chttp_ctx)=%zu\n", CHTTP_CTX_SIZE);
	printf("sizeof(struct chttp_dpage)=%zu\n", sizeof(struct chttp_dpage));

	// dynamic
	context = chttp_context_alloc();

	chttp_set_version(context, CHTTP_VERSION_1_1);
	chttp_set_method(context, "POST");
	chttp_set_url(context, "/abc");
	chttp_add_header(context, "header1", "abc123");
	chttp_add_header(context, "header2", "XYZZZZ");
	chttp_add_header(context, "header3", "....??????");

	chttp_context_debug(context);

	chttp_delete_header(context, "header1");
	chttp_delete_header(context, "header2");

	chttp_context_debug(context);

	chttp_context_free(context);

	// static
	chttp_context_init(&scontext);
	chttp_set_url(&scontext, "/123");
	chttp_context_debug(&scontext);
	chttp_context_free(&scontext);

	// custom
	context = chttp_context_init_buf(ctx_buf, sizeof(ctx_buf));
	chttp_set_url(context, "/");
	chttp_context_debug(context);
	chttp_context_free(context);

	return (0);
}
