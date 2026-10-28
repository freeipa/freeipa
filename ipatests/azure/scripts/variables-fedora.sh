#!/bin/bash -eux

# Put the platform-specific definitions here

function firewalld_cmd() {
    firewall-cmd $@
}

function installed_packages() {
    rpm -qa | sort
}
