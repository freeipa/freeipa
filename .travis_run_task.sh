#!/bin/bash

# NOTE: this script is intended to run in Travis CI only
set -ev

test_set=""
developer_mode_opt="--developer-mode"

if [[ "$TASK_TO_RUN" == "lint" ]]
then
    if [[ "$TRAVIS_EVENT_TYPE" == "pull_request" ]]
    then
        git diff origin/$TRAVIS_BRANCH -U0 | pep8 --diff &> $PEP8_ERROR_LOG ||:
    fi 

    # disable developer mode for lint task, otherwise we get an error
    developer_mode_opt=""
fi

if [[ -n "$TESTS_TO_RUN" ]]
then
    pushd ipatests
    test_set=`ls -d -1 $TESTS_TO_RUN 2> /dev/null | tr '\n' ' '`
    popd
fi

docker pull $TEST_RUNNER_IMAGE

ipa-docker-test-runner -l $CI_RESULTS_LOG \
    -c $TEST_RUNNER_CONFIG \
    $developer_mode_opt \
    --container-image $TEST_RUNNER_IMAGE \
    --git-repo $TRAVIS_BUILD_DIR \
    $TASK_TO_RUN $test_set
