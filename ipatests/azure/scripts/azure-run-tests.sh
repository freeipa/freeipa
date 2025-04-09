#!/bin/bash -eux

set -o pipefail

if [ $# -ne 1 ]; then
    echo "Docker environment ID is not provided"
    exit 1
fi

# docker uses - but podman uses _ as separator when building scaled container names
CONTAINER_SEP="_"
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

IPA_TESTS_ARGS_VARNAME="IPA_TESTS_ARGS_${PROJECT_ID}"
IPA_TESTS_ARGS="${!IPA_TESTS_ARGS_VARNAME:-}"

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

IPA_TESTS_CONTROLLER="${PROJECT_ID}${CONTAINER_SEP}master${CONTAINER_SEP}1"
IPA_TESTS_LOGSDIR="${IPA_TESTS_REPO_PATH}/ipa_envs/${IPA_TESTS_ENV_NAME}/${CI_RUNNER_LOGS_DIR}"

# path to azure scripts inside container
IPA_TESTS_SCRIPTS_IN="${IPA_TESTS_REPO_PATH}/${IPA_TESTS_SCRIPTS}"
# path to azure scripts outside of container
IPA_TESTS_SCRIPTS_OUT="${BUILD_REPOSITORY_LOCALPATH}/${IPA_TESTS_SCRIPTS}"

IPA_TESTS_NETWORK_VARNAME="IPA_TESTS_NETWORK_${PROJECT_ID}"
IPA_NETWORK=${!IPA_TESTS_NETWORK_VARNAME:-default}
IPA_TESTS_NETWORK_INTERNAL_VARNAME="IPA_TESTS_NETWORK_INTERNAL_${PROJECT_ID}"
IPA_NETWORK_INTERNAL="${!IPA_TESTS_NETWORK_INTERNAL_VARNAME:-false}"

# Docker resources
# mem_limit
IPA_TESTS_SERVER_MEM_LIMIT_VARNAME="IPA_TESTS_SERVER_MEM_LIMIT_${PROJECT_ID}"
IPA_TESTS_SERVER_MEM_LIMIT="${!IPA_TESTS_SERVER_MEM_LIMIT_VARNAME:-2000m}"

IPA_TESTS_REPLICA_MEM_LIMIT_VARNAME="IPA_TESTS_REPLICA_MEM_LIMIT_${PROJECT_ID}"
IPA_TESTS_REPLICA_MEM_LIMIT="${!IPA_TESTS_REPLICA_MEM_LIMIT_VARNAME:-2000m}"

IPA_TESTS_CLIENT_MEM_LIMIT_VARNAME="IPA_TESTS_CLIENT_MEM_LIMIT_${PROJECT_ID}"
IPA_TESTS_CLIENT_MEM_LIMIT="${!IPA_TESTS_CLIENT_MEM_LIMIT_VARNAME:-512m}"

# memswap_limit
IPA_TESTS_SERVER_MEMSWAP_LIMIT_VARNAME="IPA_TESTS_SERVER_MEMSWAP_LIMIT_${PROJECT_ID}"
IPA_TESTS_SERVER_MEMSWAP_LIMIT="${!IPA_TESTS_SERVER_MEMSWAP_LIMIT_VARNAME:-2500m}"

IPA_TESTS_REPLICA_MEMSWAP_LIMIT_VARNAME="IPA_TESTS_REPLICA_MEMSWAP_LIMIT_${PROJECT_ID}"
IPA_TESTS_REPLICA_MEMSWAP_LIMIT="${!IPA_TESTS_REPLICA_MEMSWAP_LIMIT_VARNAME:-2500m}"

IPA_TESTS_CLIENT_MEMSWAP_LIMIT_VARNAME="IPA_TESTS_CLIENT_MEMSWAP_LIMIT_${PROJECT_ID}"
IPA_TESTS_CLIENT_MEMSWAP_LIMIT="${!IPA_TESTS_CLIENT_MEMSWAP_LIMIT_VARNAME:-768m}"
#

IPA_TESTS_DOMAIN="${IPA_TESTS_DOMAIN:-ipa.test}"
# bash4
IPA_TESTS_REALM="${IPA_TESTS_DOMAIN^^}"
DOCKER_HOST=$(eval "echo unix://${XDG_RUNTIME_DIR}/podman/podman.sock")

# for base tests only 1 master is needed even if another was specified
if [ "$IPA_TESTS_TYPE" == "base" ]; then
    IPA_TESTS_CLIENTS="0"
    IPA_TESTS_REPLICAS="0"
fi

# path to env dir outside from container
project_dir="${IPA_TESTS_ENV_WORKING_DIR}/${IPA_TESTS_ENV_NAME}"

# path for journal if containers setup fails
SYSTEMD_BOOT_LOG="${project_dir}/systemd_boot_logs"

# path to directory where to dump list of packages outside of container
IPA_INSTALLED_PKGS_DIR="${project_dir}/installed_packages"

BASH_CMD="/bin/bash --noprofile --norc"

function containers() {
    local _containers="${PROJECT_ID}${CONTAINER_SEP}master${CONTAINER_SEP}1"
    # build list of replicas
    for i in $(seq 1 1 "$IPA_TESTS_REPLICAS"); do
        _containers+=" ${PROJECT_ID}${CONTAINER_SEP}replica${CONTAINER_SEP}${i}"
    done
    # build list of clients
    for i in $(seq 1 1 "$IPA_TESTS_CLIENTS"); do
        _containers+=" ${PROJECT_ID}${CONTAINER_SEP}client${CONTAINER_SEP}${i}"
    done
    printf "$_containers"
}

function compose_execute() {
    # execute given command within every container of compose
    for container in $(containers); do
        podman exec -t \
            "$container" \
            "$@" \
        2>&1 | \
        sed "s/.*/$container: &/"
    done
}

ln -sfr \
    "${IPA_TESTS_DOCKERFILES}/docker-compose.yml" \
    "$project_dir"/

ln -sfr \
    "${IPA_TESTS_DOCKERFILES}/seccomp.json" \
    "$project_dir"/

# will be generated later in setup_containers.py
touch "${project_dir}"/ipa-test-config.yaml

pushd "$project_dir"

BUILD_REPOSITORY_LOCALPATH="$BUILD_REPOSITORY_LOCALPATH" \
IPA_DOCKER_IMAGE="${IPA_DOCKER_IMAGE:-freeipa-azure-builder}" \
IPA_NETWORK="${IPA_NETWORK:-ipanet}" \
IPA_NETWORK_INTERNAL="$IPA_NETWORK_INTERNAL" \
IPA_IPV6_SUBNET="2001:db8:1:${PROJECT_ID}::/64" \
IPA_TESTS_SERVER_MEM_LIMIT="$IPA_TESTS_SERVER_MEM_LIMIT" \
IPA_TESTS_REPLICA_MEM_LIMIT="$IPA_TESTS_REPLICA_MEM_LIMIT" \
IPA_TESTS_CLIENT_MEM_LIMIT="$IPA_TESTS_CLIENT_MEM_LIMIT" \
IPA_TESTS_SERVER_MEMSWAP_LIMIT="$IPA_TESTS_SERVER_MEMSWAP_LIMIT" \
IPA_TESTS_REPLICA_MEMSWAP_LIMIT="$IPA_TESTS_REPLICA_MEMSWAP_LIMIT" \
IPA_TESTS_CLIENT_MEMSWAP_LIMIT="$IPA_TESTS_CLIENT_MEMSWAP_LIMIT" \
COMPOSE_PROJECT_NAME="$PROJECT_ID" \
PROJECT_DIR="$project_dir" \
podman-compose up \
    --scale replica="$IPA_TESTS_REPLICAS" \
    --scale client="$IPA_TESTS_CLIENTS" \
    --force-recreate --remove-orphans -d

podman network inspect ${PROJECT_ID}_${IPA_NETWORK}

popd

IPA_TESTS_CLIENTS="$IPA_TESTS_CLIENTS" \
IPA_TESTS_REPLICAS="$IPA_TESTS_REPLICAS" \
IPA_TESTS_ENV_ID="$PROJECT_ID" \
IPA_TESTS_ENV_WORKING_DIR="$IPA_TESTS_ENV_WORKING_DIR" \
IPA_TESTS_ENV_NAME="$IPA_TESTS_ENV_NAME" \
IPA_TEST_CONFIG_TEMPLATE="${BUILD_REPOSITORY_LOCALPATH}/ipatests/azure/templates/ipa-test-config-template.yaml" \
IPA_TESTS_REPO_PATH="$IPA_TESTS_REPO_PATH" \
IPA_TESTS_DOMAIN="$IPA_TESTS_DOMAIN" \
DOCKER_HOST="$DOCKER_HOST" \
IPA_NETWORK="${IPA_NETWORK:-ipanet}" \
python3 setup_containers.py || \
    { mkdir -p "$SYSTEMD_BOOT_LOG";
      for container in $(containers); do
          podman exec -t "$container" \
              $BASH_CMD -eu \
              -c 'journalctl -b --no-pager' > "${SYSTEMD_BOOT_LOG}/systemd_boot_${container}.log";
      done
      exit 1;
    }

# collect list of all the installed packages
mkdir -p "$IPA_INSTALLED_PKGS_DIR"

# controller
podman exec -t \
    --env IPA_TESTS_SCRIPTS="${IPA_TESTS_SCRIPTS_IN}" \
    --env IPA_PLATFORM="$IPA_PLATFORM" \
    "$IPA_TESTS_CONTROLLER" \
    $BASH_CMD -eu \
    -c \
    "source '${IPA_TESTS_SCRIPTS_IN}/variables.sh' && \
     echo '# Controller container: $IPA_TESTS_CONTROLLER' && \
     echo '# IPA platform: '\$IPA_PLATFORM && \
     installed_packages \
     " > "${IPA_INSTALLED_PKGS_DIR}/packages_controller_${IPA_TESTS_CONTROLLER}.log"

# display user namespace
podman exec -t \
    --env IPA_TESTS_SCRIPTS="${IPA_TESTS_SCRIPTS_IN}" \
    --env IPA_PLATFORM="$IPA_PLATFORM" \
    "$IPA_TESTS_CONTROLLER" \
    $BASH_CMD -eu \
    -c \
    "cat /proc/self/uid_map /proc/self/gid_map"

# workaround for /etc/shadow missing read permissions
# workers
for container in $(containers); do
    podman exec -t \
        --env IPA_TESTS_SCRIPTS="${IPA_TESTS_SCRIPTS_IN}" \
        --env IPA_PLATFORM="$IPA_PLATFORM" \
        "$container" \
        $BASH_CMD -eu \
        -c \
        "chmod a+r /etc/shadow"
done

# workers
for container in $(containers); do
    podman exec -t \
        --env IPA_TESTS_SCRIPTS="${IPA_TESTS_SCRIPTS_IN}" \
        --env IPA_PLATFORM="$IPA_PLATFORM" \
        "$container" \
        $BASH_CMD -eu \
        -c \
        "source '${IPA_TESTS_SCRIPTS_IN}/variables.sh' && \
         echo '# Container: $container' && \
         echo '# IPA platform: '\$IPA_PLATFORM && \
         installed_packages \
         " > "${IPA_INSTALLED_PKGS_DIR}/packages_${container}.log"
done

# path to runner within container
tests_runner="${IPA_TESTS_SCRIPTS_IN}/azure-run-${IPA_TESTS_TYPE}-tests.sh"

tests_result=1
{ podman exec -t \
    --env IPA_TESTS_SCRIPTS="${IPA_TESTS_SCRIPTS_IN}" \
    --env IPA_PLATFORM="$IPA_PLATFORM" \
    --env IPA_TESTS_DOMAIN="$IPA_TESTS_DOMAIN" \
    --env IPA_TESTS_REALM="$IPA_TESTS_REALM" \
    --env IPA_TESTS_LOGSDIR="$IPA_TESTS_LOGSDIR" \
    --env IPA_TESTS_TO_RUN="$IPA_TESTS_TO_RUN" \
    --env IPA_TESTS_TO_IGNORE="$IPA_TESTS_TO_IGNORE" \
    --env IPA_TESTS_ARGS="$IPA_TESTS_ARGS" \
    --env IPA_NETWORK_INTERNAL="$IPA_NETWORK_INTERNAL" \
    "$IPA_TESTS_CONTROLLER" \
    $BASH_CMD \
    -eux "$tests_runner" && tests_result=0 ; } || tests_result=$?

echo "Report disk usage"
compose_execute df -h

echo "Report memory statistics"
files='/sys/fs/cgroup/memory/memory.memsw.failcnt \
/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes \
/sys/fs/cgroup/memory/memory.memsw.max_usage_in_bytes \
/sys/fs/cgroup/memory/memory.failcnt \
/sys/fs/cgroup/memory/memory.max_usage_in_bytes \
/sys/fs/cgroup/memory/memory.limit_in_bytes \
/proc/sys/vm/swappiness \
'

MEMORY_STATS_PATH="$project_dir/memory.stats"
compose_execute $BASH_CMD -eu -c \
    "for file in $files; do printf '%s=%s\n' \"\$file\" \"\$(head -n 1 \$file)\" ; done" > "$MEMORY_STATS_PATH"

sed -E -n \
    's/(.*): .*(memory\.(memsw\.)?failcnt)=([0-9]+)/\1 \2 \4/p' \
    "$MEMORY_STATS_PATH" | \
tr -d '\r' | \
while read -r container memtype failcnt; do
   if [ "$failcnt" -gt 0 ]; then
      grep "^$container.*memory\..*" "$MEMORY_STATS_PATH" >> "$project_dir/memory.warnings"
   fi
done

pushd "$project_dir"
BUILD_REPOSITORY_LOCALPATH="$BUILD_REPOSITORY_LOCALPATH" \
IPA_DOCKER_IMAGE="${IPA_DOCKER_IMAGE:-freeipa-azure-builder}" \
IPA_NETWORK="${IPA_NETWORK:-ipanet}" \
IPA_NETWORK_INTERNAL="$IPA_NETWORK_INTERNAL" \
IPA_IPV6_SUBNET="2001:db8:1:${PROJECT_ID}::/64" \
IPA_TESTS_SERVER_MEM_LIMIT="$IPA_TESTS_SERVER_MEM_LIMIT" \
IPA_TESTS_REPLICA_MEM_LIMIT="$IPA_TESTS_REPLICA_MEM_LIMIT" \
IPA_TESTS_CLIENT_MEM_LIMIT="$IPA_TESTS_CLIENT_MEM_LIMIT" \
IPA_TESTS_SERVER_MEMSWAP_LIMIT="$IPA_TESTS_SERVER_MEMSWAP_LIMIT" \
IPA_TESTS_REPLICA_MEMSWAP_LIMIT="$IPA_TESTS_REPLICA_MEMSWAP_LIMIT" \
IPA_TESTS_CLIENT_MEMSWAP_LIMIT="$IPA_TESTS_CLIENT_MEMSWAP_LIMIT" \
COMPOSE_PROJECT_NAME="$PROJECT_ID" \
PROJECT_DIR="$project_dir" \
podman-compose down
popd

exit $tests_result
