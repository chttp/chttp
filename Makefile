# CHTTP Makefile

.PHONY:	all test check

all:
	$(MAKE) -C src all

%:
	$(MAKE) -C src $@

test:	check

check:
	$(MAKE) -C src chttp_test
	cd tests && ./test_all.sh
