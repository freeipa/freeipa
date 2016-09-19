#!/bin/bash -e

if [[ $# -lt 1 ]]; then
echo "Usage: $0 <outfile> [<any> <certutil> <args>]"
echo "Called as: $0 $@"
exit 1
fi

CSR="$1"
shift
certutil -R -a -z <(head -c 4096 /dev/urandom) -o "$CSR" -s CN=machine.example.com,O=DOMAIN.EXAMPLE.COM --extSAN dns:machine.example.com "$@"
