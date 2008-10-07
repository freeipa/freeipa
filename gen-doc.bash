#!/bin/bash

# Hackish script to generate documentation using epydoc

sources="ipalib ipa_server ipa_webui"
out="./freeipa2-dev-doc"

init="./ipalib/__init__.py"
echo "Looking for $init"
if [[ ! -f $init ]]
then
    echo "Error: You do not appear to be in the project directory"
    exit 1
fi
echo "You appear to be in the project directory"

# Documentation
if [[ -d $out ]]
then
    echo "Removing old $out directory"
    rm -r $out
fi
echo "Creating documentation in $out"
epydoc -v --parse-only --html --no-frames \
    --name=FreeIPA2 \
    --docformat=restructuredtext \
    --output=$out \
    $sources
