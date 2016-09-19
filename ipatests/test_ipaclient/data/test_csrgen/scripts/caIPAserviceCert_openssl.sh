#!/bin/bash -e

if [[ $# -ne 2 ]]; then
echo "Usage: $0 <outfile> <keyfile>"
echo "Called as: $0 $@"
exit 1
fi

CONFIG="$(mktemp)"
CSR="$1"
shift

echo \
'[ req ]
prompt = no
encrypt_key = no

distinguished_name = sec0
req_extensions = sec2

[ sec0 ]
O=DOMAIN.EXAMPLE.COM
CN=machine.example.com

[ sec1 ]
DNS = machine.example.com

[ sec2 ]
subjectAltName = @sec1
' > "$CONFIG"

openssl req -new -config "$CONFIG" -out "$CSR" -key $1
rm "$CONFIG"
