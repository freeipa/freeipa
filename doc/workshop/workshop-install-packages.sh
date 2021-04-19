#!/bin/bash
sudo dnf install -y freeipa-server freeipa-server-dns sssd-dbus mod_lookup_identity mod_authnz_pam haveged nmap-ncat nano pamtester bash-completion
sudo dnf clean all
