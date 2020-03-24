#!/bin/bash -eu

IPA_TESTS_ENV_WORKING_DIR="${IPA_TESTS_REPO_PATH}/ipa_envs"
COREDUMPS_DIR="${IPA_TESTS_ENV_WORKING_DIR}/${COREDUMPS_SUBDIR}"

since_time="$(cat '/coredumpctl.time.mark' || echo '-1h')"
debugger="/debugger.sh"

cat > "$debugger" <<EOF
#!/bin/bash -eux

debug_info="\$@"
gdb \
    -ex 'set confirm off' \
    -ex 'set pagination off' \
    -ex 'thread apply all bt full' \
    -ex 'quit' \
    \$debug_info > "\${CORE_PID}.stacktrace" 2>&1
EOF
chmod +x "$debugger"

# make sure coredumpctl installed
which coredumpctl
coredumpctl \
    --no-pager --directory="$HOST_JOURNAL" --since="$since_time" list ||:

rm -rvf "$COREDUMPS_DIR" ||:
mkdir "$COREDUMPS_DIR"
cd "$COREDUMPS_DIR"

pids="$(coredumpctl --no-pager --directory="$HOST_JOURNAL" --since="$since_time" -F COREDUMP_PID || echo '')"
for pid in $pids; do
    # core dump
    { coredumpctl \
        --no-pager \
        --since="$since_time" \
        --directory="$HOST_JOURNAL" \
        -o "${pid}.core" dump "$pid" && \
      tar -czf "${pid}.core.tar.gz" --remove-files "${pid}.core" ; } ||:

    # stacktrace
    { CORE_PID="$pid" \
        coredumpctl \
        --no-pager \
        --since="$since_time" \
        --directory="$HOST_JOURNAL" \
        --debugger="$debugger" \
        debug "$pid" && \
      tar \
        -czf "${pid}.stacktrace.tar.gz" \
        --remove-files "${pid}.stacktrace" ; } ||:
done

chmod a+rw -R "$COREDUMPS_DIR"
