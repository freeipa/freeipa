#!/bin/bash -eux

if [ $# -ne 1 ]; then
    echo "Docker environment ID is not provided"
    exit 1
fi

PROJECT_ID="$1"
BUILD_REPOSITORY_LOCALPATH="${BUILD_REPOSITORY_LOCALPATH:-$(realpath .)}"

IPA_TESTS_TO_RUN_VARNAME="IPA_TESTS_TO_RUN_${PROJECT_ID}"
IPA_TESTS_TO_RUN="${!IPA_TESTS_TO_RUN_VARNAME:-}"
# in case of missing explicit list of tests to be run the Pytest run all the
# discovered tests, this is an error for this CI
[ -z "$IPA_TESTS_TO_RUN" ] && { echo 'Nothing to test'; exit 1; }

IPA_TESTS_ENV_NAME_VARNAME="IPA_TESTS_ENV_NAME_${PROJECT_ID}"
IPA_TESTS_ENV_NAME="${!IPA_TESTS_ENV_NAME_VARNAME:-}"
[ -z "$IPA_TESTS_ENV_NAME" ] && \
    { echo "Project name is not set for project:${PROJECT_ID}"; exit 1 ;}

IPA_TESTS_TYPE_VARNAME="IPA_TESTS_TYPE_${PROJECT_ID}"
IPA_TESTS_TYPE="${!IPA_TESTS_TYPE_VARNAME:-integration}"

# Normalize spacing and expand the list afterwards. Remove {} for the single list element case
IPA_TESTS_TO_RUN=$(eval "echo {$(echo $IPA_TESTS_TO_RUN | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

IPA_TESTS_TO_IGNORE_VARNAME="IPA_TESTS_TO_IGNORE_${PROJECT_ID}"
IPA_TESTS_TO_IGNORE="${!IPA_TESTS_TO_IGNORE_VARNAME:-}"
[ -n "$IPA_TESTS_TO_IGNORE" ] && \
IPA_TESTS_TO_IGNORE=$(eval "echo --ignore\ {$(echo $IPA_TESTS_TO_IGNORE | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

IPA_TESTS_CLIENTS_VARNAME="IPA_TESTS_CLIENTS_${PROJECT_ID}"
IPA_TESTS_CLIENTS="${!IPA_TESTS_CLIENTS_VARNAME:-0}"

IPA_TESTS_REPLICAS_VARNAME="IPA_TESTS_REPLICAS_${PROJECT_ID}"
IPA_TESTS_REPLICAS="${!IPA_TESTS_REPLICAS_VARNAME:-0}"

IPA_TESTS_CONTROLLER="${PROJECT_ID}_master_1"
IPA_TESTS_LOGSDIR="${IPA_TESTS_REPO_PATH}/ipa_envs/${IPA_TESTS_ENV_NAME}/${CI_RUNNER_LOGS_DIR}"

IPA_TESTS_DOMAIN="${IPA_TESTS_DOMAIN:-ipa.test}"
# bash4
IPA_TESTS_REALM="${IPA_TESTS_DOMAIN^^}"

# for base tests only 1 master is needed even if another was specified
if [ "$IPA_TESTS_TYPE" == "base" ]; then
    IPA_TESTS_CLIENTS="0"
    IPA_TESTS_REPLICAS="0"
fi

project_dir="${IPA_TESTS_ENV_WORKING_DIR}/${IPA_TESTS_ENV_NAME}"
ln -sfr \
    "${IPA_TESTS_DOCKERFILES}/docker-compose.yml" \
    "$project_dir"/

# will be generated later in setup_containers.py
touch "${project_dir}"/ipa-test-config.yaml

pushd "$project_dir"

BUILD_REPOSITORY_LOCALPATH="$BUILD_REPOSITORY_LOCALPATH" \
IPA_DOCKER_IMAGE="${IPA_DOCKER_IMAGE:-freeipa-azure-builder}" \
IPA_NETWORK="${IPA_NETWORK:-ipanet}" \
IPA_IPV6_SUBNET="2001:db8:1:${PROJECT_ID}::/64" \
docker-compose -p "$PROJECT_ID" up \
    --scale replica="$IPA_TESTS_REPLICAS" \
    --scale client="$IPA_TESTS_CLIENTS" \
    --force-recreate --remove-orphans -d

popd

IPA_TESTS_CLIENTS="$IPA_TESTS_CLIENTS" \
IPA_TESTS_REPLICAS="$IPA_TESTS_REPLICAS" \
IPA_TESTS_ENV_ID="$PROJECT_ID" \
IPA_TESTS_ENV_WORKING_DIR="$IPA_TESTS_ENV_WORKING_DIR" \
IPA_TESTS_ENV_NAME="$IPA_TESTS_ENV_NAME" \
IPA_TEST_CONFIG_TEMPLATE="${BUILD_REPOSITORY_LOCALPATH}/ipatests/azure/templates/ipa-test-config-template.yaml" \
IPA_TESTS_REPO_PATH="$IPA_TESTS_REPO_PATH" \
IPA_TESTS_DOMAIN="$IPA_TESTS_DOMAIN" \
python3 setup_containers.py

# path to runner within container
tests_runner="${IPA_TESTS_REPO_PATH}/${IPA_TESTS_SCRIPTS}/azure-run-${IPA_TESTS_TYPE}-tests.sh"

tests_result=1
{ docker exec -t \
    --env IPA_TESTS_SCRIPTS="${IPA_TESTS_REPO_PATH}/${IPA_TESTS_SCRIPTS}" \
    --env IPA_PLATFORM="$IPA_PLATFORM" \
    --env IPA_TESTS_DOMAIN="$IPA_TESTS_DOMAIN" \
    --env IPA_TESTS_REALM="$IPA_TESTS_REALM" \
    --env IPA_TESTS_LOGSDIR="$IPA_TESTS_LOGSDIR" \
    --env IPA_TESTS_TO_RUN="$IPA_TESTS_TO_RUN" \
    --env IPA_TESTS_TO_IGNORE="$IPA_TESTS_TO_IGNORE" \
    "$IPA_TESTS_CONTROLLER" \
    /bin/bash --noprofile --norc \
    -eux "$tests_runner" && tests_result=0 ; } || tests_result=$?

pushd "$project_dir"
BUILD_REPOSITORY_LOCALPATH="$BUILD_REPOSITORY_LOCALPATH" \
IPA_DOCKER_IMAGE="${IPA_DOCKER_IMAGE:-freeipa-azure-builder}" \
IPA_NETWORK="${IPA_NETWORK:-ipanet}" \
IPA_IPV6_SUBNET="2001:db8:1:${PROJECT_ID}::/64" \
docker-compose -p "$PROJECT_ID" down
popd

exit $tests_result
