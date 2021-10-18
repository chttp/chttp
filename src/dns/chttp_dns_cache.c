/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "data/queue.h"
#include "data/tree.h"

#include <pthread.h>
#include <string.h>

#define _DNS_CACHE_PREALLOC_SIZE		100
#define _DNS_CACHE_HOSTNAME_MAX			256


long CHTTP_DNS_CACHE_TTL = 600;

struct _dns_cache_entry {
	unsigned int					magic;
#define _DNS_CACHE_ENTRY_MAGIC				0x435870E5

	char						hostname[_DNS_CACHE_HOSTNAME_MAX];

	RB_ENTRY(_dns_cache_entry)			tree_entry;
	TAILQ_ENTRY(_dns_cache_entry)			list_entry;

	struct _dns_cache_entry				*next;
	size_t						length;
	size_t						current;

	struct chttp_addr				addr;
};

static struct {
	unsigned int					magic;
#define _DNS_CACHE_MAGIC				0xF37F6BA4

	pthread_mutex_t					lock;

	int						initialized;

	RB_HEAD(_dns_cache_tree, _dns_cache_entry)	cache_tree;
	TAILQ_HEAD(, _dns_cache_entry)			free_list;
	TAILQ_HEAD(, _dns_cache_entry)			lru_list;

	struct _dns_cache_entry				entries[_DNS_CACHE_PREALLOC_SIZE];

	struct {
		size_t					lookups;
		size_t					cache_hits;
		size_t					dups;
		size_t					expired;
	} stats;
} _DNS_CACHE = {
	_DNS_CACHE_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	RB_INITIALIZER(_DNS_CACHE.cache_tree),
	TAILQ_HEAD_INITIALIZER(_DNS_CACHE.free_list),
	TAILQ_HEAD_INITIALIZER(_DNS_CACHE.lru_list),
	{{0}},
	{0}
};

static int _dns_cache_cmp(const struct _dns_cache_entry *k1, const struct _dns_cache_entry *k2);

RB_GENERATE_STATIC(_dns_cache_tree, _dns_cache_entry, tree_entry, _dns_cache_cmp)

static inline void
_dns_cache_ok()
{
	assert(_DNS_CACHE.magic == _DNS_CACHE_MAGIC);
}

static inline void
_dns_cache_LOCK()
{
	_dns_cache_ok();
	assert_zero(pthread_mutex_lock(&_DNS_CACHE.lock));
}

static inline void
_dns_cache_UNLOCK()
{
	_dns_cache_ok();
	assert_zero(pthread_mutex_unlock(&_DNS_CACHE.lock));
}

static void
_dns_cache_init()
{
	size_t i;

	_dns_cache_ok();

	assert(RB_EMPTY(&_DNS_CACHE.cache_tree));
	assert(TAILQ_EMPTY(&_DNS_CACHE.free_list));
	assert(TAILQ_EMPTY(&_DNS_CACHE.lru_list));

	/* Create the free_list */
	for (i = 0; i < _DNS_CACHE_PREALLOC_SIZE; i++) {
		assert_zero(_DNS_CACHE.entries[i].magic);
		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, &_DNS_CACHE.entries[i], list_entry);
	}

	_DNS_CACHE.initialized = 1;
}

static int
_dns_cache_cmp(const struct _dns_cache_entry *k1, const struct _dns_cache_entry *k2)
{
	return strcmp(k1->hostname, k2->hostname);
}

void
chttp_dns_cache_lookup(const char *host, size_t host_len, struct chttp_addr *addr_dest)
{
	struct _dns_cache_entry *result, find;

	_dns_cache_ok();
	assert(host);
	assert(host_len);
	assert(addr_dest);

	if (host_len >= _DNS_CACHE_HOSTNAME_MAX) {
		return;
	}

	_dns_cache_LOCK();

	if (!_DNS_CACHE.initialized) {
		_dns_cache_init();
		assert(_DNS_CACHE.initialized);
	}

	strncpy(find.hostname, host, host_len + 1);

	result = RB_FIND(_dns_cache_tree, &_DNS_CACHE.cache_tree, &find);

	if (result) {
		assert(result->magic == _DNS_CACHE_ENTRY_MAGIC);
		// TODO

		_dns_cache_UNLOCK();
		return;
	}

	_dns_cache_UNLOCK();
}
