#!/bin/bash -eux

# Put the platform-specific definitions here

function firewalld_cmd() {
    firewall-cmd $@
}
