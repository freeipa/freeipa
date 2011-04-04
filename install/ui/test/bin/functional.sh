#!/bin/sh

BIN_DIR=`dirname $0`

TEST_SUITES=functional
TEST_RESULTS=results
mkdir -p "$TEST_RESULTS"

LIST=$1
shift

while [ -n "$1" ]
do
    LIST="$LIST $1"
    shift
done

if [ -z "$LIST" ]
then
    LIST="`ls $TEST_SUITES/*-suite.html | sed 's/^.*\/\(.*\)-suite.html$/\1/'`"
fi

for TEST_NAME in $LIST
do
    echo ===================================================
    echo Test Suite: $TEST_NAME
    echo ===================================================

    "$BIN_DIR/selenium.sh" "$TEST_SUITES/$TEST_NAME-suite.html"\
        "$TEST_RESULTS/$TEST_NAME-results.html"

    rhino -opt -1 "$BIN_DIR/selenium-results.js" "$TEST_RESULTS/$TEST_NAME-results.html"
done
