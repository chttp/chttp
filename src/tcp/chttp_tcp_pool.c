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

static struct chttp_tcp_pool_entry *
_tcp_pool_get_entry(void)
{
	struct chttp_tcp_pool_entry *entry, *prev = NULL;

	chttp_tcp_pool_ok();

	if (!TAILQ_EMPTY(&_TCP_POOL.free_list)) {
		entry = TAILQ_FIRST(&_TCP_POOL.free_list);
		assert(entry);

		TAILQ_REMOVE(&_TCP_POOL.free_list, entry, list_entry);

		return entry;
	} else if (!TAILQ_EMPTY(&_TCP_POOL.lru_list)) {
		// Pull from the LRU
		entry = TAILQ_LAST(&_TCP_POOL.lru_list, chttp_tcp_pool_list);
		chttp_pool_entry_ok(entry);

		if (!entry->next) {
			assert(RB_REMOVE(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry));
			TAILQ_REMOVE(&_TCP_POOL.lru_list, entry, list_entry);
		} else {
			// Pull the last entry
			while (entry->next) {
				prev = entry;
				entry = entry->next;
				chttp_pool_entry_ok(entry);
			}

			assert(prev->next == entry);
			prev->next = NULL;
		}

		chttp_addr_connected(&entry->addr);
		chttp_addr_close(&entry->addr);

		_TCP_POOL.stats.nuked++;

		return entry;
	}

	return NULL;
}

void
chttp_tcp_pool_store(struct chttp_addr *addr)
{
	struct chttp_tcp_pool_entry *entry, *head;

	chttp_tcp_pool_ok();
	chttp_addr_connected(addr);

	if (_TCP_POOL_AGE_SEC <= 0) {
		chttp_addr_close(addr);
		return;
	}

	_tcp_pool_LOCK();

	if (!_TCP_POOL.initialized) {
		_tcp_pool_init();
	}
	assert(_TCP_POOL.initialized);

	entry = _tcp_pool_get_entry();

	if (!entry) {
		chttp_addr_close(addr);
		_tcp_pool_UNLOCK();
		return;
	}

	chttp_ZERO(entry);
	entry->magic = CHTTP_TCP_POOL_ENTRY_MAGIC;

	chttp_addr_clone(&entry->addr, addr);

	// TODO expiration

	head = RB_INSERT(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry);

	if (head) {
		chttp_pool_entry_ok(entry);
		chttp_addr_connected(&entry->addr);

		// Remove the head and add it behind the entry
		assert(RB_REMOVE(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, head));
		TAILQ_REMOVE(&_TCP_POOL.lru_list, head, list_entry);

		entry->next = head;

		assert_zero(RB_INSERT(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry));
	}

	TAILQ_INSERT_HEAD(&_TCP_POOL.lru_list, entry, list_entry);

	_tcp_pool_UNLOCK();

	chttp_addr_resolved(addr);
}

void
chttp_tcp_pool_close(void)
{
	struct chttp_tcp_pool_entry *entry, *temp, *next;
	size_t size;

	_tcp_pool_LOCK();

	if (!_TCP_POOL.initialized) {
		_tcp_pool_UNLOCK();
		return;
	}

	TAILQ_FOREACH_SAFE(entry, &_TCP_POOL.lru_list, list_entry, temp) {
		chttp_pool_entry_ok(entry);

		assert(RB_REMOVE(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry));
		TAILQ_REMOVE(&_TCP_POOL.lru_list, entry, list_entry);

		while (entry) {
			chttp_pool_entry_ok(entry);

			next = entry->next;

			chttp_addr_connected(&entry->addr);
			chttp_addr_close(&entry->addr);
			chttp_addr_reset(&entry->addr);

			chttp_ZERO(entry);

			TAILQ_INSERT_TAIL(&_TCP_POOL.free_list, entry, list_entry);

			entry = next;
		}
	}

	assert(RB_EMPTY(&_TCP_POOL.pool_tree));
	assert(TAILQ_EMPTY(&_TCP_POOL.lru_list));

	size = 0;
	TAILQ_FOREACH(entry, &_TCP_POOL.free_list, list_entry) {
		size++;
	}
	assert(size == _TCP_POOL_SIZE);

	_tcp_pool_UNLOCK();
}