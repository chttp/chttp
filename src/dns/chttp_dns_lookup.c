/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <netdb.h>
#include <string.h>
#include <sys/types.h>

//temp
#include <arpa/inet.h>
#include <stdio.h>

void
chttp_dns_lookup(struct chttp_context *ctx, const char *host)
{
	struct addrinfo *ai_res_list, *ai_res;
	struct addrinfo hints;
	int ret;

	char tmp[128];

	chttp_context_ok(ctx);
	assert(host && *host);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, NULL, &hints, &ai_res_list);

	printf("*** ret %d\n", ret);

	if (ret) {
		ctx->error = CHTTP_ERR_DNS;
	}

	for (ai_res = ai_res_list; ai_res; ai_res = ai_res->ai_next) {
		switch(ai_res->ai_addr->sa_family) {
			case AF_INET:
				inet_ntop(AF_INET, &(((struct sockaddr_in*)ai_res->ai_addr)->sin_addr),
				    tmp, sizeof(tmp));
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, &(((struct sockaddr_in6*)ai_res->ai_addr)->sin6_addr),
				    tmp, sizeof(tmp));
				break;
			default:
				strncpy(tmp, "unknown address", sizeof(tmp));
				break;
		}
		printf("*** found %s\n", tmp);
	}

	freeaddrinfo(ai_res_list);
}
