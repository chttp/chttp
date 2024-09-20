/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "dns/chttp_dns_cache.h"

#include <stdio.h>

long _DNS_CACHE_TTL = CHTTP_DNS_CACHE_TTL;
size_t _DNS_CACHE_SIZE = CHTTP_DNS_CACHE_SIZE;

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
_dns_cache_LOCK(void)
{
	chttp_dns_cache_ok();
	assert_zero(pthread_mutex_lock(&_DNS_CACHE.lock));
}

static inline void
_dns_cache_UNLOCK(void)
{
	chttp_dns_cache_ok();
	assert_zero(pthread_mutex_unlock(&_DNS_CACHE.lock));
}

static void
_dns_cache_init(void)
{
	size_t i;

	chttp_dns_cache_ok();
	assert_zero(_DNS_CACHE.initialized);
	assert(_DNS_CACHE_SIZE <= CHTTP_DNS_CACHE_SIZE);

	assert(RB_EMPTY(&_DNS_CACHE.cache_tree));
	assert(TAILQ_EMPTY(&_DNS_CACHE.free_list));
	assert(TAILQ_EMPTY(&_DNS_CACHE.lru_list));

	/* Create the free_list */
	for (i = 0; i < _DNS_CACHE_SIZE; i++) {
		assert_zero(_DNS_CACHE.entries[i].magic);
		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, &_DNS_CACHE.entries[i], list_entry);
	}

	_DNS_CACHE.initialized = 1;
}

static int
_dns_cache_cmp(const struct chttp_dns_cache_entry *k1, const struct chttp_dns_cache_entry *k2)
{
	chttp_dns_entry_ok(k1);
	chttp_dns_entry_ok(k2);

	return strcmp(k1->hostname, k2->hostname);
}

int
chttp_dns_cache_lookup(const char *host, size_t host_len, struct chttp_addr *addr_dest, int port,
    unsigned int flags)
{
	struct chttp_dns_cache_entry *addr_head, *addr, find;
	size_t pos;
	double now;

	chttp_dns_cache_ok();
	assert(host);
	assert(host_len);
	assert(addr_dest);

	if (_DNS_CACHE_TTL <= 0) {
		return 0;
	}

	if (host_len >= CHTTP_DNS_CACHE_HOST_MAX) {
		chttp_safe_add(&_DNS_CACHE.stats.err_too_long, 1);
		return 0;
	}

	_dns_cache_LOCK();

	if (!_DNS_CACHE.initialized) {
		_dns_cache_init();
	}
	assert(_DNS_CACHE.initialized);

	_DNS_CACHE.stats.lookups++;

	find.magic = CHTTP_DNS_CACHE_ENTRY_MAGIC;
	strncpy(find.hostname, host, host_len + 1);

	addr_head = RB_FIND(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, &find);

	if (!addr_head) {
		_dns_cache_UNLOCK();
		return 0;
	}

	chttp_dns_entry_ok(addr_head);

	addr = addr_head;
	pos = 0;

	// Calculate next for RR
	if (!(flags & DNS_DISABLE_RR)) {
		pos = (addr_head->current + 1) % addr_head->length;
		addr_head->current = pos;
	}

	while (pos > 0) {
		addr = addr->next;
		chttp_dns_entry_ok(addr);

		pos--;
	}

	assert(addr->addr.state == CHTTP_ADDR_CACHED ||
		addr->addr.state == CHTTP_ADDR_STALE);

	// Move to the front of the LRU
	if (TAILQ_FIRST(&_DNS_CACHE.lru_list) != addr_head) {
		TAILQ_REMOVE(&_DNS_CACHE.lru_list, addr_head, list_entry);
		TAILQ_INSERT_HEAD(&_DNS_CACHE.lru_list, addr_head, list_entry);

		_DNS_CACHE.stats.lru++;
	}

	now = chttp_get_time();
	assert(addr_head->expiration);

	if (addr_head->expiration < now) {
		// Expired, mark as stale and add more time
		// Force this client to do a fresh lookup
		addr_head->addr.state = CHTTP_ADDR_STALE;
		addr_head->expiration = now + 10;

		_DNS_CACHE.stats.expired++;

		_dns_cache_UNLOCK();

		return 0;
	}

	chttp_dns_copy(addr_dest, &addr->addr.sa, port);
	chttp_addr_resolved(addr_dest);

	_DNS_CACHE.stats.cache_hits++;

	_dns_cache_UNLOCK();

	return 1;
}

static void
_dns_free_entry(struct chttp_dns_cache_entry *dns_head)
{
	struct chttp_dns_cache_entry *dns_entry, *dns_temp;

	chttp_dns_cache_ok();

	dns_entry = dns_head;

	while (dns_entry) {
		chttp_dns_entry_ok(dns_entry);

		dns_temp = dns_entry;
		dns_entry = dns_entry->next;

		chttp_addr_reset(&dns_temp->addr);
		chttp_ZERO(dns_temp);

		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, dns_temp, list_entry);
	}
}

static void
_dns_remove_entry(struct chttp_dns_cache_entry *dns_entry)
{
	chttp_dns_cache_ok();
	chttp_dns_entry_ok(dns_entry);

	assert(RB_REMOVE(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_entry));
	TAILQ_REMOVE(&_DNS_CACHE.lru_list, dns_entry, list_entry);

	_dns_free_entry(dns_entry);
}

static struct chttp_dns_cache_entry *
_dns_get_entry(void)
{
	struct chttp_dns_cache_entry *entry;

	chttp_dns_cache_ok();

	if (!TAILQ_EMPTY(&_DNS_CACHE.free_list)) {
		entry = TAILQ_FIRST(&_DNS_CACHE.free_list);
		assert(entry);

		TAILQ_REMOVE(&_DNS_CACHE.free_list, entry, list_entry);

		return entry;
	} else if (!TAILQ_EMPTY(&_DNS_CACHE.lru_list)) {
		// Pull from the LRU
		entry = TAILQ_LAST(&_DNS_CACHE.lru_list, chttp_dns_cache_list);
		chttp_dns_entry_ok(entry);

		_dns_remove_entry(entry);

		_DNS_CACHE.stats.nuked++;

		assert(!TAILQ_EMPTY(&_DNS_CACHE.free_list));

		return _dns_get_entry();
	}

	return NULL;
}

void
chttp_dns_cache_store(const char *host, size_t host_len, struct addrinfo *ai_list)
{
	struct addrinfo *ai_entry;
	struct chttp_dns_cache_entry *dns_entry, *dns_head, *dns_last;
	size_t count;

	chttp_dns_cache_ok();
	assert(_DNS_CACHE.initialized);
	assert(host);
	assert(host_len);
	assert(ai_list);

	if (_DNS_CACHE_TTL <= 0) {
		return;
	}

	if (host_len >= CHTTP_DNS_CACHE_HOST_MAX) {
		chttp_safe_add(&_DNS_CACHE.stats.err_too_long, 1);
		return;
	}

	_dns_cache_LOCK();

	if (!_DNS_CACHE.initialized) {
		_dns_cache_init();
	}
	assert(_DNS_CACHE.initialized);

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

		chttp_ZERO(dns_entry);
		dns_entry->magic = CHTTP_DNS_CACHE_ENTRY_MAGIC;

		chttp_dns_copy(&dns_entry->addr, ai_entry->ai_addr, 0);
		chttp_addr_resolved(&dns_entry->addr);

		dns_entry->addr.state = CHTTP_ADDR_CACHED;

		count++;
		_DNS_CACHE.stats.insertions++;

		dns_last = dns_entry;
	}

	assert(dns_head);

	dns_head->length = count;
	dns_head->expiration = chttp_get_time() + _DNS_CACHE_TTL;
	strncpy(dns_head->hostname, host, host_len + 1);

	TAILQ_INSERT_HEAD(&_DNS_CACHE.lru_list, dns_head, list_entry);
	dns_entry = RB_INSERT(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_head);

	if (dns_entry) {
		chttp_dns_entry_ok(dns_entry);
		chttp_addr_ok(&dns_entry->addr);

		if (dns_entry->addr.state == CHTTP_ADDR_CACHED) {
			_DNS_CACHE.stats.dups++;
		}

		_dns_remove_entry(dns_entry);

		assert_zero(RB_INSERT(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_head));
	}

	_dns_cache_UNLOCK();
}