# CHTTP Makefile (tests)

CHTTP_TEST=../src/chttp_test
CHTTP_TEST_FLAGS=
CHTS=$(wildcard */*.cht)
VALGRIND=

.PHONY:	all test check chttp_test valgrind

all:		check

FORCE:

chttp_test:
		$(MAKE) -C .. chttp_test

valgrind:	VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
valgrind:	check

test:		check

check:		CHTTP_TEST_FLAGS=-q
check:		$(CHTS)

verbose:	$(CHTS)

%.cht:		chttp_test FORCE
		$(VALGRIND) $(CHTTP_TEST) $(CHTTP_TEST_FLAGS) $@

