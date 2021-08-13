# CHTTP Makefile (tests)

CHTTP_TEST=../src/chttp_test
CHTS=$(wildcard */*.cht)

.PHONY:	all test check chttp_test

all:		check

FORCE:

chttp_test:
		$(MAKE) -C .. chttp_test

test:		check

check:		chttp_test $(CHTS)

%.cht:		FORCE
		$(CHTTP_TEST) $@

