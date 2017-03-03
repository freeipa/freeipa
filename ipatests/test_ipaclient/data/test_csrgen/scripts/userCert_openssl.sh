#!/bin/bash -e

if [[ $# -lt 2 ]]; then
echo "Usage: $0 <outfile> <keyfile> <other openssl arguments>"
echo "Called as: $0 $@"
exit 1
fi

CONFIG="$(mktemp)"
CSR="$1"
KEYFILE="$2"
shift; shift

echo \
'[ req ]
prompt = no
encrypt_key = no

distinguished_name = sec0
req_extensions = sec2

[ sec0 ]
O=DOMAIN.EXAMPLE.COM
CN=testuser

[ sec1 ]
email = testuser@example.com

[ sec2 ]
subjectAltName = @sec1
' > "$CONFIG"

openssl req -new -config "$CONFIG" -out "$CSR" -key "$KEYFILE" "$@"
rm "$CONFIG"
