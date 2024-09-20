/*
 * Copyright (c) 2024 chttp
 *
 */

#include "test/chttp_test.h"
#include "tcp/chttp_tcp_pool.h"

extern long _TCP_POOL_AGE_SEC;
extern size_t _TCP_POOL_SIZE;

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

			printf("\t_TCP_POOL.pool_tree: %zu %s:%d age=%lf *ptr=%p\n", count,
				host, port, entry->expiration - chttp_get_time(), (void*)entry);

			entry = entry->next;
			count++;
		}
	}

	printf("\t_TCP_POOL.pool_tree=%zu\n", pool_size);
}

void
chttp_test_cmd_tcp_pool_debug(struct chttp_test_context *ctx,
    struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	chttp_test_ERROR_param_count(cmd, 0);
	test = chttp_test_convert(ctx);

	if (test->verbocity >= CHTTP_LOG_VERBOSE) {
		_tcp_pool_debug();
	}
}