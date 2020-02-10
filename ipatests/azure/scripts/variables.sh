#!/bin/bash -eu

HTTPD_SYSTEMD_NAME='httpd.service'
HTTPD_LOGDIR='/var/log/httpd'
HTTPD_ERRORLOG="${HTTPD_LOGDIR}/error_log"
HTTPD_BASEDIR='/etc/httpd'
HTTPD_ALIASDIR="${HTTPD_BASEDIR}/alias"
BIND_BASEDIR='/var/named'
BIND_DATADIR="${BIND_BASEDIR}/data"

function firewalld_cmd() { :; }

# this should be the last to override base variables with platform specific
source "$IPA_TESTS_SCRIPTS/variables-${IPA_PLATFORM}.sh"
