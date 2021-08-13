# CHTTP Makefile

.PHONY:	all test check chttp_test

all:
		$(MAKE) -C src all

%:
		$(MAKE) -C src $@

chttp_test:
		$(MAKE) -C src chttp_test

test:		check

check:		chttp_test
		cd tests && ./test_all.sh
