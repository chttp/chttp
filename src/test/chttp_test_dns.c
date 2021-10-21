/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"
#include "dns/chttp_dns_cache.h"

#include <stdlib.h>

extern size_t _DNS_CACHE_SIZE;

struct chttp_test_dns {
	unsigned int				magic;
#define _DNS_MAGIC				0x6CF2F95F

	char					value[256];
	char					stat_str[64];
};

static void
_dns_finish(struct chttp_test_context *ctx)
{
	assert(ctx);
	assert(ctx->dns);
	assert(ctx->dns->magic == _DNS_MAGIC);

	chttp_ZERO(ctx->dns);
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

		chttp_ZERO(ctx->dns);

		ctx->dns->magic = _DNS_MAGIC;

		chttp_test_register_finish(ctx, "dns", _dns_finish);
	}

	assert(ctx->dns->magic == _DNS_MAGIC);
}

void
chttp_test_cmd_dns_cache_size(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	long size;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	size = chttp_test_parse_long(cmd->params[0].value);
	assert(size > 0);

	_DNS_CACHE_SIZE = size;

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "DNS cache size %zu", _DNS_CACHE_SIZE);
}

void
chttp_test_cmd_dns_lookup_or_skip(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_addr addr, *paddr;
	int fresh = 0, ret;

	_dns_init(ctx);
	chttp_test_ERROR(cmd->param_count < 1 || cmd->param_count > 2,
		"invalid parameter count");

	if (cmd->param_count == 2) {
		fresh = 1;
	}

	paddr = &addr;

	ret = chttp_addr_lookup(&addr, cmd->params[0].value, cmd->params[0].len, 1, fresh);

	if (ret) {
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "cannot resolve address %s",
			cmd->params[0].value);
		return;
	}

	chttp_addr_resolved(paddr);

	chttp_sa_string(&addr.sa, ctx->dns->value, sizeof(ctx->dns->value), &ret);
	assert(ret == 1);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "DNS result %s", ctx->dns->value);
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
chttp_dns_cache_debug(void)
{
	struct chttp_dns_cache_entry *dns_entry, *dns_temp;
	size_t tree_count = 0, tree_sub_count = 0;
	size_t lru_count = 0, lru_sub_count = 0, free_count = 0, sub_count;
	char name[256];
	int port;

	assert(_DNS_CACHE.magic == CHTTP_DNS_CACHE_MAGIC);

	printf("_DNS_CACHE\n");

	RB_FOREACH(dns_entry, chttp_dns_cache_tree, &_DNS_CACHE.cache_tree) {
		assert(dns_entry->magic == CHTTP_DNS_CACHE_ENTRY_MAGIC);
		chttp_addr_ok(&dns_entry->addr);
		assert(dns_entry->addr.state == CHTTP_ADDR_CACHED);

		printf("\tRB entry: '%s'\n", dns_entry->hostname);
		tree_count++;
		sub_count = 1;

		chttp_addr_ok(&dns_entry->addr);
		chttp_sa_string(&dns_entry->addr.sa, name, sizeof(name), &port);
		printf("\t\t%s:%d\n", name, port);

		dns_temp = dns_entry->next;
		while(dns_temp) {
			assert(dns_temp->magic == CHTTP_DNS_CACHE_ENTRY_MAGIC);
			chttp_addr_ok(&dns_temp->addr);
			assert(dns_temp->addr.state == CHTTP_ADDR_CACHED);

			tree_sub_count++;
			sub_count++;

			chttp_addr_ok(&dns_temp->addr);
			chttp_sa_string(&dns_temp->addr.sa, name, sizeof(name), &port);
			printf("\t\t%s:%d\n", name, port);

			dns_temp = dns_temp->next;
		}

		assert(sub_count == dns_entry->length);
		assert(dns_entry->current < dns_entry->length);
	}
	printf("\tRB count: %zu (%zu)\n", tree_count, tree_count + tree_sub_count);

	TAILQ_FOREACH(dns_entry, &_DNS_CACHE.lru_list, list_entry) {
		assert(dns_entry->magic == CHTTP_DNS_CACHE_ENTRY_MAGIC);

		printf("\tLRU entry: '%s'\n", dns_entry->hostname);
		lru_count++;

		dns_temp = dns_entry->next;
		while(dns_temp) {
			assert(dns_temp->magic == CHTTP_DNS_CACHE_ENTRY_MAGIC);
			lru_sub_count++;
			dns_temp = dns_temp->next;
		}
	}
	printf("\tLRU count: %zu (%zu)\n", lru_count, lru_count + lru_sub_count);

	TAILQ_FOREACH(dns_entry, &_DNS_CACHE.free_list, list_entry) {
		free_count++;
	}
	printf("\tFREE count: %zu\n", free_count);
	printf("\tTOTAL count: %zu (%zu %zu)\n", _DNS_CACHE_SIZE,
		free_count + tree_count + tree_sub_count,
		free_count + lru_count + lru_sub_count);

	printf("\tstats.lookups: %zu\n", _DNS_CACHE.stats.lookups);
	printf("\tstats.cache_hits: %zu\n", _DNS_CACHE.stats.cache_hits);
	printf("\tstats.insertions: %zu\n", _DNS_CACHE.stats.insertions);
	printf("\tstats.dups: %zu\n", _DNS_CACHE.stats.dups);
	printf("\tstats.expired: %zu\n", _DNS_CACHE.stats.expired);
	printf("\tstats.nuked: %zu\n", _DNS_CACHE.stats.nuked);
	printf("\tstats.lru: %zu\n", _DNS_CACHE.stats.lru);
	printf("\tstats.err_too_long: %zu\n", _DNS_CACHE.stats.err_too_long);
	printf("\tstats.err_alloc: %zu\n", _DNS_CACHE.stats.err_alloc);
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

char *
chttp_test_var_dns_value(struct chttp_test_context *ctx)
{
	_dns_init(ctx);

	return ctx->dns->value;
}

#define _DNS_STATS_NAME(name)							\
char *										\
chttp_test_var_dns_##name(struct chttp_test_context *ctx)			\
{										\
	_dns_init(ctx);								\
	assert(_DNS_CACHE.magic == CHTTP_DNS_CACHE_MAGIC);			\
										\
	snprintf(ctx->dns->stat_str, sizeof(ctx->dns->stat_str), "%zu",		\
		_DNS_CACHE.stats.name);						\
										\
	return ctx->dns->stat_str;						\
}

_DNS_STATS_NAME(lookups)
_DNS_STATS_NAME(cache_hits)
_DNS_STATS_NAME(insertions)
_DNS_STATS_NAME(dups)
_DNS_STATS_NAME(expired)
_DNS_STATS_NAME(nuked)
_DNS_STATS_NAME(lru)
_DNS_STATS_NAME(err_too_long)
_DNS_STATS_NAME(err_alloc)