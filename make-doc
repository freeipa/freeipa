#!/bin/bash

# Hackish script to generate documentation using epydoc

sources="ipalib ipaserver ipatests"
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

epydoc -v --html --no-frames --include-log \
    --name="FreeIPA v2 developer documentation" \
    --docformat=restructuredtext \
    --output=$out \
    $sources
