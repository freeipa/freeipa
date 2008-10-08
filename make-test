#!/bin/bash

# Script to run nosetests under multiple versions of Python

versions="python2.4 python2.5 python2.6"

for name in $versions
do
    executable="/usr/bin/$name"
    if [[ -f $executable ]]; then
        echo "[ $name: Starting tests... ]"
        ((runs += 1))
        if $executable /usr/bin/nosetests -v
        then
            echo "[ $name: Tests OK ]"
        else
            echo "[ $name: Tests FAILED ]"
            ((failures += 1))
        fi
    else
        echo "[ $name: Not found ]"
    fi
    echo ""
done

if [ $failures ]; then
    echo "[ Ran under $runs version(s); FAILED under $failures version(s) ]"
    exit $failures
else
    echo "[ Ran under $runs version(s); all OK ]"
fi
