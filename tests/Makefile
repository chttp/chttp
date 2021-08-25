# CHTTP Makefile (tests)

CHTTP_TEST=../src/chttp_test
V=v
CHTS=$(sort $(wildcard */*.cht))
VALGRIND=

.PHONY:	all test check chttp_test valgrind verbose

all:		check

FORCE:

chttp_test:
		$(MAKE) -C .. chttp_test

valgrind:	VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
valgrind:	check

test:		check

check:		V=q
check:		$(CHTS)

verbose:	$(CHTS)

%.cht:		chttp_test FORCE
		$(VALGRIND) $(CHTTP_TEST) -$(V) $@

