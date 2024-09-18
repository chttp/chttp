/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "chttp_tcp_pool.h"

long _TCP_POOL_AGE_SEC = CHTTP_TCP_POOL_AGE_SEC;
size_t _TCP_POOL_SIZE = CHTTP_TCP_POOL_SIZE;

struct chttp_tcp_pool _TCP_POOL = {
	CHTTP_TCP_POOL_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	RB_INITIALIZER(_TCP_POOL.pool_tree),
	TAILQ_HEAD_INITIALIZER(_TCP_POOL.free_list),
	TAILQ_HEAD_INITIALIZER(_TCP_POOL.lru_list),
	{{0}},
	{0}
};

static int _tcp_pool_cmp(const struct chttp_tcp_pool_entry *k1,
	const struct chttp_tcp_pool_entry *k2);

RB_GENERATE(chttp_tcp_pool_tree, chttp_tcp_pool_entry, tree_entry, _tcp_pool_cmp)

static inline void
_tcp_pool_LOCK(void)
{
	chttp_tcp_pool_ok();
	assert_zero(pthread_mutex_lock(&_TCP_POOL.lock));
}

static inline void
_tcp_pool_UNLOCK(void)
{
	chttp_tcp_pool_ok();
	assert_zero(pthread_mutex_unlock(&_TCP_POOL.lock));
}

static void
_tcp_pool_init(void)
{
	size_t i;

	chttp_tcp_pool_ok();
	assert_zero(_TCP_POOL.initialized);
	assert(_TCP_POOL_SIZE <= CHTTP_TCP_POOL_SIZE);

	assert(RB_EMPTY(&_TCP_POOL.pool_tree));
	assert(TAILQ_EMPTY(&_TCP_POOL.free_list));
	assert(TAILQ_EMPTY(&_TCP_POOL.lru_list));

	/* Create the free_list */
	for (i = 0; i < _TCP_POOL_SIZE; i++) {
		assert_zero(_TCP_POOL.entries[i].magic);
		TAILQ_INSERT_TAIL(&_TCP_POOL.free_list, &_TCP_POOL.entries[i], list_entry);
	}

	_TCP_POOL.initialized = 1;
}

static int
_tcp_pool_cmp(const struct chttp_tcp_pool_entry *k1, const struct chttp_tcp_pool_entry *k2)
{
	chttp_pool_entry_ok(k1);
	chttp_pool_entry_ok(k2);

	return chttp_addr_cmp(&k1->addr, &k2->addr);
}

int
chttp_tcp_pool_lookup(struct chttp_addr *addr)
{
	chttp_tcp_pool_ok();
	chttp_addr_resolved(addr);

	addr->reused = 0;

	_tcp_pool_LOCK();

	if (!_TCP_POOL.initialized) {
		_tcp_pool_init();
	}
	assert(_TCP_POOL.initialized);

	_TCP_POOL.stats.lookups++;

	_tcp_pool_UNLOCK();

	return 0;
}

void
chttp_tcp_pool_store(struct chttp_addr *addr)
{
	(void)addr;
}