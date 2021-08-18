# CHTTP Makefile

.PHONY:	all test check

all:
		$(MAKE) -C src $@

test:		check

check:		chttp_test
		$(MAKE) -C tests $@

%:
		$(MAKE) -C src $@
