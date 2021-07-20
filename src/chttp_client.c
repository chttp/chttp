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

	// dynamic
	context = chttp_context_alloc();
	context_debug(context);
	chttp_context_free(context);

	// static
	chttp_context_init(&scontext);
	context_debug(&scontext);
	chttp_context_free(&scontext);

	// custom
	context = chttp_context_init_buf(ctx_buf, sizeof(ctx_buf));
	context_debug(context);
	chttp_context_free(context);

	return (0);
}
