/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "dns/chttp_dns_cache.h"

#include <stdio.h>
#include <string.h>

long CHTTP_DNS_CACHE_TTL = 600;

struct chttp_dns_cache _DNS_CACHE = {
	CHTTP_DNS_CACHE_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	RB_INITIALIZER(_DNS_CACHE.cache_tree),
	TAILQ_HEAD_INITIALIZER(_DNS_CACHE.free_list),
	TAILQ_HEAD_INITIALIZER(_DNS_CACHE.lru_list),
	{{0}},
	{0}
};

static int _dns_cache_cmp(const struct chttp_dns_cache_entry *k1,
	const struct chttp_dns_cache_entry *k2);

RB_GENERATE(chttp_dns_cache_tree, chttp_dns_cache_entry, tree_entry, _dns_cache_cmp)

static inline void
_dns_cache_ok(void)
{
	assert(_DNS_CACHE.magic == CHTTP_DNS_CACHE_MAGIC);
}

static inline void
_dns_cache_LOCK(void)
{
	_dns_cache_ok();
	assert_zero(pthread_mutex_lock(&_DNS_CACHE.lock));
}

static inline void
_dns_cache_UNLOCK(void)
{
	_dns_cache_ok();
	assert_zero(pthread_mutex_unlock(&_DNS_CACHE.lock));
}

static void
_dns_cache_init(void)
{
	size_t i;

	_dns_cache_ok();
	assert_zero(_DNS_CACHE.initialized);

	assert(RB_EMPTY(&_DNS_CACHE.cache_tree));
	assert(TAILQ_EMPTY(&_DNS_CACHE.free_list));
	assert(TAILQ_EMPTY(&_DNS_CACHE.lru_list));

	/* Create the free_list */
	for (i = 0; i < CHTTP_DNS_CACHE_SIZE; i++) {
		assert_zero(_DNS_CACHE.entries[i].magic);
		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, &_DNS_CACHE.entries[i], list_entry);
	}

	_DNS_CACHE.initialized = 1;
}

static int
_dns_cache_cmp(const struct chttp_dns_cache_entry *k1, const struct chttp_dns_cache_entry *k2)
{
	assert(k1);
	assert(k2);

	return strcmp(k1->hostname, k2->hostname);
}

void
chttp_dns_cache_lookup(const char *host, size_t host_len, struct chttp_addr *addr_dest)
{
	struct chttp_dns_cache_entry *addr_head, find;

	_dns_cache_ok();
	assert(host);
	assert(host_len);
	assert(addr_dest);

	if (host_len >= CHTTP_DNS_CACHE_HOST_MAX) {
		chttp_safe_add(&_DNS_CACHE.stats.err_too_long, 1);
		return;
	}

	_dns_cache_LOCK();

	_DNS_CACHE.stats.lookups++;

	if (!_DNS_CACHE.initialized) {
		_dns_cache_init();
		assert(_DNS_CACHE.initialized);
	}

	strncpy(find.hostname, host, host_len + 1);

	addr_head = RB_FIND(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, &find);

	if (addr_head) {
		assert(addr_head->magic == CHTTP_DNS_CACHE_ENTRY_MAGIC);
		// TODO choose the next entry, LRU the head

		_DNS_CACHE.stats.cache_hits++;

		_dns_cache_UNLOCK();
		return;
	}

	_dns_cache_UNLOCK();
}

static void
_dns_free_entry(struct chttp_dns_cache_entry *dns_head)
{
	struct chttp_dns_cache_entry *dns_entry, *dns_temp;

	_dns_cache_ok();

	dns_entry = dns_head;

	while (dns_entry) {
		dns_temp = dns_entry;
		dns_entry = dns_entry->next;

		chttp_addr_reset(&dns_temp->addr);

		dns_temp->next = NULL;
		dns_temp->hostname[0] = '\0';
		dns_temp->magic = 0;

		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, dns_temp, list_entry);
	}
}

static struct chttp_dns_cache_entry *
_dns_get_entry(void)
{
	struct chttp_dns_cache_entry *entry;

	_dns_cache_ok();

	if (!TAILQ_EMPTY(&_DNS_CACHE.free_list)) {
		entry = TAILQ_FIRST(&_DNS_CACHE.free_list);
		assert(entry);

		TAILQ_REMOVE(&_DNS_CACHE.free_list, entry, list_entry);

		return entry;
	} else if (!TAILQ_EMPTY(&_DNS_CACHE.lru_list)) {
		// Pull from the LRU
		entry = TAILQ_LAST(&_DNS_CACHE.lru_list, chttp_dns_cache_lru);
		assert(entry);

		TAILQ_REMOVE(&_DNS_CACHE.lru_list, entry, list_entry);

		_DNS_CACHE.stats.nuked++;

		_dns_free_entry(entry);
		assert(!TAILQ_EMPTY(&_DNS_CACHE.free_list));

		// Grab from the free_list
		entry = TAILQ_FIRST(&_DNS_CACHE.free_list);
		assert(entry);

		TAILQ_REMOVE(&_DNS_CACHE.free_list, entry, list_entry);

		return entry;
	}

	return NULL;
}

void
chttp_dns_cache_store(const char *host, size_t host_len, struct addrinfo *ai_list, int port)
{
	struct addrinfo *ai_entry;
	struct chttp_dns_cache_entry *dns_entry, *dns_head, *dns_last;
	size_t count;

	_dns_cache_ok();
	assert(_DNS_CACHE.initialized);
	assert(host);
	assert(host_len);
	assert(ai_list);
	assert(port >= 0 && port <= UINT16_MAX);

	if (host_len >= CHTTP_DNS_CACHE_HOST_MAX) {
		chttp_safe_add(&_DNS_CACHE.stats.err_too_long, 1);
		return;
	}

	_dns_cache_LOCK();

	dns_head = NULL;
	dns_last = NULL;
	count = 0;

	for (ai_entry = ai_list; ai_entry; ai_entry = ai_entry->ai_next) {
		dns_entry = _dns_get_entry();

		if (!dns_entry) {
			_dns_free_entry(dns_head);
			_DNS_CACHE.stats.err_alloc++;
			return;
		}

		if (!dns_head) {
			dns_head = dns_entry;
		} else {
			assert(dns_last);
			dns_last->next = dns_entry;
		}

		dns_entry->magic = CHTTP_DNS_CACHE_ENTRY_MAGIC;
		dns_entry->next = NULL;
		dns_entry->length = 0;
		dns_entry->current = 0;

		chttp_addr_copy(&dns_entry->addr, ai_entry, 0);

		count++;
		_DNS_CACHE.stats.insertions++;

		dns_last = dns_entry;
	}

	assert(dns_head);

	dns_head->length = count;
	strncpy(dns_head->hostname, host, host_len + 1);

	TAILQ_INSERT_HEAD(&_DNS_CACHE.lru_list, dns_head, list_entry);
	RB_INSERT(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_head);

	_dns_cache_UNLOCK();
}