#!/bin/bash

# Hackish script to run unit tests under both Python 2.4 and 2.5

interpreters="python2.4 python2.5"

for name in $interpreters
do
    executable="/usr/bin/$name"
    if [[ -f $executable ]]
    then
        echo "[ $0: running unit tests under $name ]"
        $executable /usr/bin/nosetests
    else
        echo "[ $0: $name not found ]"
    fi
done
