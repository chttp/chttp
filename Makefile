# CHTTP Makefile

SRC=src
TEST_CLIENT=chttp_test
TESTS=tests
TEST_ALL=test_all.sh

.PHONY:	all test check

all:
	$(MAKE) -C $(SRC) all

%:
	$(MAKE) -C $(SRC) $@

test:	check

check:
	$(MAKE) -C $(SRC) $(TEST)
	cd $(TESTS) && ./$(TEST_ALL)
