#!/bin/bash

# Authors:
#    Petr Vobornik <pvoborni@redhat.com>
#
#  Copyright (C) 2012 Red Hat
#  see file 'COPYING' for use and warranty information
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
set -o errexit

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RDIR=$DIR/../release

usage() {
cat <<-__EOF__;
NAME
     change-profile.sh - Changes development enviroment.

SYNOPSIS
     path/to/change-profile.sh [--help] [--profile] NAME

DESCRIPTION
     Changes symbolic links to switch between development profiles. Run
     with --git-ignore option to prevent git change notifications.

OPTIONS
     --help         print the help message

     -p PROFILE
     --profile PROFILE
                    allsource: both dojo, freeipa uses source files
                    compiled: both dojo, freeipa uses compiled versions
                    source: dojo compiled, freeipa source files
                    default: source
    --git-ignore
                    set git --assume-unchanged on dojo and freeipa symlinks
    --git-undo
                    undo --git-ignore

__EOF__
}

args=`getopt -u -l help,profile:,git-ignore,git-undo p: $*`

if test $? != 0
then
    usage
    exit 1
fi

set -- $args
for i
do
    case "$i" in
        --help)
            shift;
            HELP=1
            ;;
        --profile | -p)
            shift;
            PROFILE=$1
            shift;
            ;;
        --git-ignore)
            shift;
            GIT_IGNORE=1
            ;;
        --git-undo)
            shift;
            GIT_UNDO=1
            ;;
        *)
            ;;
    esac
done

set -- $args

if [[ $HELP ]] ; then
    usage
    exit 0
fi

if [[ $# = 2 ]] ; then
    PROFILE=$2
fi

if [[ $# = 1 ]] ; then
    PROFILE='source'
fi

printprofile() {
    echo "Setting profile: $PROFILE"
}


pushd $DIR/../js
    rm -f ./dojo
    rm -f ./freeipa

    case "$PROFILE" in
        'source')
            printprofile
            ln -s ../build/dojo ./dojo
            ln -s ../src/freeipa ./freeipa
            ;;
        'allsource')
            printprofile
            ln -s ../src/dojo ./dojo
            ln -s ../src/freeipa ./freeipa
            ;;
        'compiled')
            printprofile
            ln -s ../build/dojo ./dojo
            ln -s ../build/freeipa ./freeipa
            ;;
        *)
            echo "Error: Unknown profile: $PROFILE"
            ;;
    esac

    if [[ $GIT_IGNORE ]] ; then
        git update-index --assume-unchanged ./dojo
        git update-index --assume-unchanged ./freeipa
    fi

    if [[ $GIT_UNDO ]] ; then
        git update-index --no-assume-unchanged ./dojo
        git update-index --no-assume-unchanged ./freeipa
    fi
popd
