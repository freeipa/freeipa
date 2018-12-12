#!/bin/bash -x
#
# Copyright (C) 2017 FreeIPA Contributors see COPYING for license
#
# NOTE: this script is intended to run in Travis CI only

test_set=""

env_opt=""

case "$TASK_TO_RUN" in
    lint|tox)
        # disable developer mode for lint and tox tasks.
        developer_mode_opt=""
        ;;
    *)
        developer_mode_opt="--developer-mode"
        ;;
esac

function truncate_log_to_test_failures() {
    # chop off everything in the CI_RESULTS_LOG preceding pytest error output
    # if there are pytest errors in the log
    error_fail_regexp='\(=== ERRORS ===\)\|\(=== FAILURES ===\)'

    if grep -e "$error_fail_regexp" $CI_RESULTS_LOG > /dev/null
    then
        sed -i "/$error_fail_regexp/,\$!d" $CI_RESULTS_LOG
    fi
}

if [[ "$TASK_TO_RUN" == "lint" ]]
then
    if [[ "$TRAVIS_EVENT_TYPE" == "pull_request" ]]
    then
        git diff origin/$TRAVIS_BRANCH -U0 | \
            pycodestyle --ignore=W504 --diff &> $PEP8_ERROR_LOG ||:
    fi
fi

if [[ -n "$TESTS_TO_RUN" ]]
then
    pushd ipatests
    test_set=`ls -d -1 $TESTS_TO_RUN 2> /dev/null | tr '\n' ' '`
    popd
fi

echo Trying to pull docker image
docker pull $TEST_RUNNER_IMAGE

echo "Executing test runner for ${TASK_TO_RUN}"
ipa-docker-test-runner -l $CI_RESULTS_LOG \
    -c $TEST_RUNNER_CONFIG \
    $developer_mode_opt \
    --container-environment "RPMBUILD_OPTS=$env_opt" \
    --container-image $TEST_RUNNER_IMAGE \
    --git-repo $TRAVIS_BUILD_DIR \
    $TASK_TO_RUN $test_set

exit_status="$?"

if [[ "$exit_status" -ne 0 ]]
then
    truncate_log_to_test_failures
fi

exit $exit_status
