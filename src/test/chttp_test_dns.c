/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>
#include <string.h>

struct chttp_test_dns {
	unsigned int				magic;
#define _DNS_MAGIC				0x6CF2F95F

	char					name[256];
	char					stat_str[64];
};

static void
_dns_finish(struct chttp_test_context *ctx)
{
	assert(ctx);
	assert(ctx->dns);
	assert(ctx->dns->magic == _DNS_MAGIC);

	ctx->dns->magic = 0;
	free(ctx->dns);

	ctx->dns = NULL;
}

static void
_dns_init(struct chttp_test_context *ctx)
{
	assert(ctx);

	if (!ctx->dns) {
		ctx->dns = malloc(sizeof(*ctx->dns));
		assert(ctx->dns);

		memset(ctx->dns, 0, sizeof(*ctx->dns));

		ctx->dns->magic = _DNS_MAGIC;

		chttp_test_register_finish(ctx, "dns", _dns_finish);
	}

	assert(ctx->dns->magic == _DNS_MAGIC);
}

void
chttp_test_cmd_dns_lookup_or_skip(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_addr addr, *paddr;
	int ret;

	_dns_init(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	paddr = &addr;

	ret = chttp_addr_lookup(&addr, cmd->params[0].value, cmd->params[0].len, 1);

	if (ret) {
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "cannot resolve address %s",
			cmd->params[0].value);
		return;
	}

	chttp_addr_ok(paddr);

	chttp_sa_string(&addr.sa, ctx->dns->name, sizeof(ctx->dns->name), &ret);
	assert(ret == 1);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "DNS result %s", ctx->dns->name);
}

void
chttp_test_cmd_dns_lookup(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	test = chttp_test_convert(ctx);

	chttp_test_cmd_dns_lookup_or_skip(ctx, cmd);

	chttp_test_ERROR(test->skip, "dns lookup failed");
}

void
chttp_test_cmd_dns_debug(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	_dns_init(ctx);
	chttp_test_ERROR_param_count(cmd, 0);
	test = chttp_test_convert(ctx);

	if (test->verbocity >= CHTTP_LOG_VERBOSE) {
		chttp_dns_cache_debug();
	}
}

#define _DNS_STATS_NAME(name)							\
char * chttp_test_var_dns_##name(struct chttp_test_context *ctx)		\
{										\
	const struct chttp_dns_stats *stats;					\
										\
	_dns_init(ctx);								\
										\
	stats = chttp_dns_stats();						\
	snprintf(ctx->dns->stat_str, sizeof(ctx->dns->stat_str), "%zu",		\
		stats->name);							\
										\
	return ctx->dns->stat_str;						\
}

_DNS_STATS_NAME(lookups)
_DNS_STATS_NAME(cache_hits)
_DNS_STATS_NAME(insertions)
_DNS_STATS_NAME(dups)
_DNS_STATS_NAME(expired)
_DNS_STATS_NAME(nuked)
_DNS_STATS_NAME(err_too_long)
_DNS_STATS_NAME(err_alloc)