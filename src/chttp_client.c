/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>

int
main(int argc, char **argv) {
	struct chttp_context *context, scontext;
	struct chttp_context_small scontext_small;
	struct chttp_context_large scontext_large;

	printf("chttp client %s\n", CHTTP_VERSION);

	// dynamic
	context = chttp_context_alloc();
	context_debug(context);
	chttp_context_free(context);

	// static
	chttp_context_init(&scontext);
	context_debug(&scontext);
	chttp_context_free(&scontext);

	// static small
	context = chttp_context_init_small(&scontext_small);
	context_debug(context);
	chttp_context_free(context);

	// static large
	context = chttp_context_init_large(&scontext_large);
	context_debug(context);
	chttp_context_free(context);

	return (0);
}
