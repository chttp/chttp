/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "data/tree.h"

struct chttp_dns_cache
{
	int x;
};

static struct chttp_dns_cache _DNS_CACHE = {
	0
};

void
chttp_dns_cache_lookup()
{
	(void)_DNS_CACHE;
}
