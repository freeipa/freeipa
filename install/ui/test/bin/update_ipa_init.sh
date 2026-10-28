#!/bin/bash

FIXTURE_DIR=$1

INIT_FILE=$FIXTURE_DIR/ipa_init.json

usage(){
        echo "$0 {FIXTURE_DIR}"
        exit 1
}

if [ ! -f $INIT_FILE ]
then
        usage
        exit 1
fi

json="{
    \"method\": \"batch\",
    \"params\": [
        [
            {
                \"method\": \"user_find\",
                \"params\":[[], { \"whoami\": true, \"all\": true }]
            },
            {
                \"method\": \"env\",
                \"params\": [[], {}]
            },
            {
                \"method\": \"dns_is_enabled\",
                \"params\": [[], {}]
            }
        ],
        {}
    ]
}"

curl -v\
 -H "Content-Type: application/json"\
 -H "Accept: applicaton/json"\
 -H "Referer: https://`hostname`/ipa/xml"\
 --negotiate\
 --delegation always\
 -u :\
 --cacert /etc/ipa/ca.crt\
 -d "$json"\
 -X POST\
 https://`hostname`/ipa/json | sed 's/[ \t]*$//' >   $INIT_FILE
