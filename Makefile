# CHTTP Makefile

.PHONY:	all test check chttp_test

all:
		$(MAKE) -C src $@

%:
		$(MAKE) -C src $@

test:		check

check:		chttp_test
		$(MAKE) -C tests $@
