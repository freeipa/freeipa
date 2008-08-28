#!/bin/bash

# Script to run nosetests under multiple versions of Python

versions="python2.4 python2.5 python2.6"

for name in $versions
do
    echo ""
    executable="/usr/bin/$name"
    if [[ -f $executable ]]; then
        echo "[ $name: Starting tests... ]"
        if $executable /usr/bin/nosetests
        then
            echo "[ $name: Tests OK ]"
        else
            echo "[ $name: Tests FAILED ]"
            ((failures += 1))
        fi
    else
        echo "[ $name: Not found ]"
    fi
done

if [ $failures ]; then
    echo ""
    echo "[ FAILED under $failures version(s) ]"
    exit $failures
fi
