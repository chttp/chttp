# CHTTP Makefile

SRC=src
TEST=chttp_test

.PHONY:	all test check

all:
	$(MAKE) -C $(SRC) all

%:
	$(MAKE) -C $(SRC) $@

test:	check

check:
	$(MAKE) -C $(SRC) $(TEST)
