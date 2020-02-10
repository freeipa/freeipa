#!/bin/bash -ex

# Normalize spacing and expand the list afterwards. Remove {} for the single list element case
tests_to_run=$(eval "echo {$(echo $TESTS_TO_RUN | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')
tests_to_ignore=
[[ -n "$TESTS_TO_IGNORE" ]] && \
tests_to_ignore=$(eval "echo --ignore\ {$(echo $TESTS_TO_IGNORE | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')
tests_to_dedicate=
[[ -n "$TESTS_TO_DEDICATE" ]] && \
tests_to_dedicate=$(eval "echo --slice-dedicated={$(echo $TESTS_TO_DEDICATE | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

tests_dir="/freeipa/$CI_RUNNER_LOGS_DIR"
mkdir -p "$tests_dir"
cd "$tests_dir"

export IPATEST_YAML_CONFIG=~/.ipa/ipa-test-config.yaml

echo "Run IPA tests"
ipa-run-tests \
    ${tests_to_ignore} \
    ${tests_to_dedicate} \
    --slices=${SYSTEM_TOTALJOBSINPHASE:-1} \
    --slice-num=${SYSTEM_JOBPOSITIONINPHASE:-1} \
    --logging-level=debug \
    --logfile-dir="$tests_dir" \
    --verbose --with-xunit ${tests_to_run}

tests_result=$?
find "$tests_dir" -mindepth 1 -maxdepth 1 -not -name '.*' -type d \
    -exec tar --remove-files -czf {}.tar.gz {} \;

exit $tests_result
