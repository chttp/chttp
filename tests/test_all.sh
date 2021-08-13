#!/bin/bash

# CHTTP run all tests

set -e

CHTTP_TEST="../src/chttp_test"

if [ ! -x "${CHTTP_TEST}" ]
then
	echo "ERROR: ${CHTTP_TEST} cannot be executed"
	exit 1
fi

for CHTFILE in $(find * -type f -name "*.cht" | sort)
do
	echo "${CHTFILE}"
	${CHTTP_TEST} ${CHTFILE}
done

exit 0
