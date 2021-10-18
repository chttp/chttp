/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "data/queue.h"
#include "data/tree.h"

#include <pthread.h>

#define _DNS_CACHE_PREALLOC_SIZE		100
#define _DNS_CACHE_HOSTNAME_MAX			256


long CHTTP_DNS_CACHE_TTL = 600;

struct _dns_entry {
	unsigned int				magic;
#define _DNS_ENTRY_MAGIC			0x435870E5

	char					hostname[_DNS_CACHE_HOSTNAME_MAX];

	RB_ENTRY(_dns_entry)			tree_entry;
	TAILQ_ENTRY(_dns_entry)			list_entry;

	struct chttp_addr			addr;
};

static struct {
	unsigned int				magic;
#define _DNS_CACHE_MAGIC			0xF37F6BA4

	pthread_mutex_t                         lock;

	int					initialized;

	RB_HEAD(, _dns_entry)			cache_tree;
	TAILQ_HEAD(, _dns_entry)		free_list;
	TAILQ_HEAD(, _dns_entry)		lru_list;

	struct _dns_entry			entries[_DNS_CACHE_PREALLOC_SIZE];

	struct {
		size_t				lookups;
		size_t				cache_hits;
		size_t				dups;
		size_t				expired;
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

#define _dns_cache_ok()								\
	do {									\
		assert(_DNS_CACHE.magic == _DNS_CACHE_MAGIC);			\
	} while (0)

void
chttp_dns_cache_lookup()
{
	_dns_cache_ok();
}
