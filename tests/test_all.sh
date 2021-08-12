#!/bin/bash

# CHTTP run all tests

set -e

CHTTP_TEST="../src/chttp_test"

if [ ! -x "${CHTTP_TEST}" ]
then
	echo "ERROR: ${CHTTP_TEST} cannot be executed"
	exit 1
fi

${CHTTP_TEST}

exit 0
