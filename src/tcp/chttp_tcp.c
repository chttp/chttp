/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

int
chttp_tcp_connect(const struct sockaddr *sa)
{
	int s, val;
	socklen_t s_len;

	switch(sa->sa_family) {
		case AF_INET:
			s_len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			s_len = sizeof(struct sockaddr_in6);
			break;
		default:
			return (-1);
	}

	s = socket(sa->sa_family, SOCK_STREAM, 0);

	if (s < 0) {
		return (s);
	}

	val = 1;
	assert(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)));

	val = 1;
	assert(setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val)));

	val = connect(s, sa, s_len);

	if (val) {
		return (-1);
	}

	// TODO non blocking timeout (EINPROGRESS)

	return (s);
}
