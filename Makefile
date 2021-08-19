# CHTTP Makefile

.PHONY:	all test check

all:
		$(MAKE) -C src $@

test:		check

check:
		$(MAKE) -C tests $@

%:
		$(MAKE) -C src $@
