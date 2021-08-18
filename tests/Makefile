# CHTTP Makefile (tests)

CHTTP_TEST=../src/chttp_test
CHTTP_TEST_FLAGS=-q
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

check:		chttp_test $(CHTS)

%.cht:		FORCE
		$(VALGRIND) $(CHTTP_TEST) $(CHTTP_TEST_FLAGS) $@

