#!/bin/bash -eux

# this script is intended to be run within container
#
# distro-specifics
source "${IPA_TESTS_SCRIPTS}/variables.sh"

rm -rf "$IPA_TESTS_LOGSDIR"
mkdir "$IPA_TESTS_LOGSDIR"
pushd "$IPA_TESTS_LOGSDIR"

tests_result=1
{ IPATEST_YAML_CONFIG=~/.ipa/ipa-test-config.yaml \
    ipa-run-tests \
    --logging-level=debug \
    --logfile-dir="$IPA_TESTS_LOGSDIR" \
    --with-xunit \
    --verbose \
    $IPA_TESTS_TO_IGNORE \
    $IPA_TESTS_TO_RUN && tests_result=0 ; } || \
    tests_result=$?

# fix permissions on logs to be readable by Azure's user (vsts)
chmod -R o+rX "$IPA_TESTS_LOGSDIR"

find "$IPA_TESTS_LOGSDIR" -mindepth 1 -maxdepth 1 -not -name '.*' -type d \
    -exec tar --remove-files -czf {}.tar.gz {} \;

exit $tests_result
