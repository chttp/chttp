/*
 * Copyright (c) 2024 chttp
 *
 */

#include "test/chttp_test.h"
#include "tcp/chttp_tcp_pool.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


extern double _TCP_POOL_AGE_SEC;
extern size_t _TCP_POOL_SIZE;

struct chttp_test_tcp_pool {
	unsigned int				magic;
#define _TCP_POOL_MAGIC				0xB1C2DA94

	char					stat_str[64];
};

static void
_tcp_pool_finish(struct chttp_test_context *ctx)
{
	assert(ctx);
	assert(ctx->tcp_pool);
	assert(ctx->tcp_pool->magic == _TCP_POOL_MAGIC);

	chttp_ZERO(ctx->tcp_pool);
	free(ctx->tcp_pool);

	ctx->tcp_pool = NULL;
}

void
_tcp_pool_init(struct chttp_test_context *ctx)
{
	assert(ctx);

	if (!ctx->tcp_pool) {
		ctx->tcp_pool = malloc(sizeof(*ctx->tcp_pool));
		assert(ctx->tcp_pool);

		chttp_ZERO(ctx->tcp_pool);

		ctx->tcp_pool->magic = _TCP_POOL_MAGIC;

		chttp_test_register_finish(ctx, "tcp_pool", _tcp_pool_finish);

		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "tcp pool initialized");
	}

	assert(ctx->tcp_pool->magic == _TCP_POOL_MAGIC);
}

void
chttp_test_cmd_tcp_pool_age_ms(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	long ttl;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	ttl = chttp_test_parse_long(cmd->params[0].value);

	_TCP_POOL_AGE_SEC = ((double)ttl) / 1000;

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "tcp pool age %lf", _TCP_POOL_AGE_SEC);
}

void
chttp_test_cmd_tcp_pool_size(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	long size;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	size = chttp_test_parse_long(cmd->params[0].value);
	assert(size > 0);

	_TCP_POOL_SIZE = size;

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "tcp pool size %zu", _TCP_POOL_SIZE);
}

void
chttp_test_cmd_tcp_pool_fake_connect(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	int fd;

	assert(ctx);
	chttp_context_ok(ctx->chttp);
	chttp_test_ERROR_param_count(cmd, 0);

	fd = open("/dev/null", O_RDWR);
	assert(fd >= 0);

	ctx->chttp->addr.sock = fd;
	ctx->chttp->addr.state = CHTTP_ADDR_CONNECTED;
	ctx->chttp->state = CHTTP_STATE_IDLE;

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "tcp pool faked connection");
}

static void
_tcp_pool_debug(void)
{
	struct chttp_tcp_pool_entry *entry, *temp;
	size_t free_size = 0, lru_size = 0, pool_size = 0, count;
	char host[256];
	int port;

	chttp_tcp_pool_ok();

	printf("_TCP_POOL\n");

	TAILQ_FOREACH(entry, &_TCP_POOL.free_list, list_entry) {
		assert_zero(entry->magic);
		free_size++;
	}

	printf("\t_TCP_POOL.free_list=%zu\n", free_size);

	TAILQ_FOREACH(entry, &_TCP_POOL.lru_list, list_entry) {
		chttp_pool_entry_ok(entry);
		chttp_addr_connected(&entry->addr);

		lru_size++;

		chttp_sa_string(&entry->addr.sa, host, sizeof(host), &port);

		printf("\t_TCP_POOL.lru_list: %s:%d age=%lf *ptr=%p\n", host, port,
			entry->expiration - chttp_get_time(), (void*)entry);
	}

	printf("\t_TCP_POOL.lru_list=%zu\n", lru_size);

	RB_FOREACH_SAFE(entry, chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, temp) {
		count = 0;

		while (entry) {
			chttp_pool_entry_ok(entry);
			chttp_addr_connected(&entry->addr);

			pool_size++;

			chttp_sa_string(&entry->addr.sa, host, sizeof(host), &port);

			printf("\t_TCP_POOL.pool_tree: %zu %s:%d age=%lf *ptr=%p fd=%d\n",
				count, host, port, entry->expiration - chttp_get_time(),
				(void*)entry, entry->addr.sock);

			entry = entry->next;
			count++;
		}
	}

	printf("\t_TCP_POOL.pool_tree=%zu\n", pool_size);

	printf("\tstats.lookups: %zu\n", _TCP_POOL.stats.lookups);
	printf("\tstats.cache_hits: %zu\n", _TCP_POOL.stats.cache_hits);
	printf("\tstats.cache_misses: %zu\n", _TCP_POOL.stats.cache_misses);
	printf("\tstats.insertions: %zu\n", _TCP_POOL.stats.insertions);
	printf("\tstats.expired: %zu\n", _TCP_POOL.stats.expired);
	printf("\tstats.deleted: %zu\n", _TCP_POOL.stats.deleted);
	printf("\tstats.nuked: %zu\n", _TCP_POOL.stats.nuked);
	printf("\tstats.lru: %zu\n", _TCP_POOL.stats.lru);
	printf("\tstats.err_alloc: %zu\n", _TCP_POOL.stats.err_alloc);
}

void
chttp_test_cmd_tcp_pool_debug(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	chttp_test_ERROR_param_count(cmd, 0);
	test = chttp_test_convert(ctx);

	_tcp_pool_init(ctx);

	if (test->verbocity >= CHTTP_LOG_VERBOSE) {
		_tcp_pool_debug();
	}
}

#define _TCP_POOL_STATS_NAME(name)							\
char *										\
chttp_test_var_tcp_pool_##name(struct chttp_test_context *ctx)			\
{										\
	_tcp_pool_init(ctx);							\
	chttp_tcp_pool_ok();							\
										\
	snprintf(ctx->tcp_pool->stat_str, sizeof(ctx->tcp_pool->stat_str),	\
		"%zu", _TCP_POOL.stats.name);					\
										\
	return ctx->tcp_pool->stat_str;						\
}

_TCP_POOL_STATS_NAME(lookups)
_TCP_POOL_STATS_NAME(cache_hits)
_TCP_POOL_STATS_NAME(cache_misses)
_TCP_POOL_STATS_NAME(insertions)
_TCP_POOL_STATS_NAME(expired)
_TCP_POOL_STATS_NAME(deleted)
_TCP_POOL_STATS_NAME(nuked)
_TCP_POOL_STATS_NAME(lru)
_TCP_POOL_STATS_NAME(err_alloc)
