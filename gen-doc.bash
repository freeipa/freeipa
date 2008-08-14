#!/bin/bash

# Hackish script to generate documentation using epydoc

mod="ipalib"
d="./$mod-doc"
f="$d.tar.bz2"

init="./$mod/__init__.py"
echo "Looking for $init"
if [[ ! -f $init ]]
then
    echo "Error: You do not appear to be in the project directory"
    exit 1
fi
echo "You appear to be in the project directory"

# Documentation
if [[ -d $d ]]
then
    echo "Removing old $d directory"
    rm -r $d
fi
echo "Creating documentation in $d"
epydoc -v --output=$d --docformat=restructuredtext --html --no-frames $mod

# Tarball
if [[ -f $f ]]
then
    echo "Removing old $f file"
    rm $f
fi
echo "Creating tarball $f"
tar --create --bzip2 --file=$f $d
