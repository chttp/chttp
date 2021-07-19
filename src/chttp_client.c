/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>

int
main(int argc, char **argv) {
	printf("chttp client %s\n", CHTTP_VERSION);

	chttp_context_alloc();

	return (0);
}
