#!/bin/sh

TEST_SUITE=$1
TEST_RESULTS=$2

if [ "$TEST_SUITE" = "" -o "$TEST_RESULTS" = "" ]
then
    echo "Usage: $0 <test suite> <test results>"
    exit 1
fi

if [ ! -f "$TEST_SUITE" ]
then
    echo "Error: Test suite $TEST_SUITE not found."
    exit 1
fi

PROFILE_DIR="$HOME/.mozilla/firefox"
PROFILE=`ls "$PROFILE_DIR" | grep .default`
PROFILE_TEMPLATE="$PROFILE_DIR/$PROFILE"

# Run Selenium Test
java -Djava.util.logging.config.file=conf/logger.properties\
    -jar /usr/share/java/selenium-server-standalone.jar\
    -firefoxProfileTemplate "$PROFILE_TEMPLATE"\
    -htmlSuite "*firefox" "http://localhost" "$TEST_SUITE" "$TEST_RESULTS"

# Kill Firefox
ps -ef|grep -i firefox|grep '\-profile'|awk '{print $2;}'|xargs kill
