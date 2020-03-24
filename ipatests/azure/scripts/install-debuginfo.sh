#!/bin/bash -eu

function install_debuginfo() { :; }

# override install_debuginfo for the platform specifics
source "${IPA_TESTS_SCRIPTS}/install-debuginfo-${IPA_PLATFORM}.sh"

install_debuginfo
