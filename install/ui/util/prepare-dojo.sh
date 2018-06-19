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

#
# This script prepares working enviroment to use dojo toolkit.
#
# It checkouts public git mirrors of dojo svns then applies custom patches and
# makes symbolic links from install/ui/js/dojo and install/ui/js/util

# freeipa/install/ui absolute path - to use when this script is not run from
# install/ui directory

usage() {
cat <<-__EOF__;
NAME
     prepare-dojo.sh - prepare FreeIPA Web UI developmnent enviroment to work
                       with Dojo Library

SYNOPSIS
     path/to/prepare-dojo.sh [--help] [--all] [other options]

DESCRIPTION
     prepare-dojo.sh is a shell script which prepares FreeIPA Web UI enviroment
     for creating custom Dojo/Dojo or Dojo/Util/Build builds.

OPTIONS
     --help         print the help message

     --clone        clone git repository

     --checkout     checkout git repository

     --patches      applies custom patches, must be used with --checkout

     --links        makes symbolic links from src directory to Dojo directory

     --dojo         work with Dojo

     --util         work with Util

     --all          Do --clone --checkout --patches --links --dojo --util

     --branch <br>  Specify a Dojo branch/tag/hash to checkout, default: 1.8.3

     --dir <dir>    Specify a clone dir, default: freeipa/../dojo/
__EOF__
}

if [ "$#" = "0" ] ; then
    usage
    exit 0
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# relative path for target dir to checkout dojo
DOJO_DIR=$DIR/../../../../dojo

# working version of Dojo toolkit
BRANCH='1.13.0'
YES='YES'

args=`getopt -q -u -l help,checkout,clone,patches,links,dojo,util,all,branch:,dir: a $*`

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
            HELP=$YES
            ;;
        --checkout)
            shift;
            CHECKOUT=$YES
            ;;
        --clone)
            shift;
            CLONE=$YES
            ;;
        --patches)
            shift;
            PATCHES=$YES
            ;;
        --links)
            shift;
            LINKS=$YES
            ;;
        --dojo)
            shift;
            DOJO=$YES
            ;;
        --util)
            shift;
            UTIL=$YES
            ;;
        --all | -a)
            shift;
            CHECKOUT=$YES
            CLONE=$YES
            PATCHES=$YES
            LINKS=$YES
            DOJO=$YES
            UTIL=$YES
            ALL=$YES
            ;;
        --branch)
            shift;
            BRANCH=$1
            shift;
            ;;
        --dir)
            shift;
            DOJO_DIR=$1
            shift;
            ;;
        *)
            ;;
    esac
done

if [[ $HELP = $YES ]] ; then
    usage
    exit 0
fi

if [ ! -d $DOJO_DIR ] ; then
    mkdir $DOJO_DIR
fi

# clone dojo git repositories
pushd $DOJO_DIR

if [[ $DOJO = $YES ]] ; then
    if [[ $CLONE = $YES ]] ; then
        git clone https://github.com/dojo/dojo.git
    fi
    pushd dojo
        if [[ $CHECKOUT = $YES ]] ; then
            git clean -dfx
            git checkout master
            git fetch --tags
            git fetch
            git branch -D $BRANCH
            git checkout $BRANCH
        fi
    popd

    if [[ $LINKS = $YES ]] ; then
        rm -f $DIR/../src/dojo
        ln -s $DOJO_DIR/dojo $DIR/../src/dojo
    fi
fi

if [[ $UTIL = $YES ]] ; then
    if [[ $CLONE = $YES ]] ; then
        git clone https://github.com/dojo/util.git
    fi
    pushd util
        if [[ $CHECKOUT = $YES ]] ; then
            git clean -dfx
            git checkout master
            git fetch --tags
            git fetch
            git branch -D $BRANCH
            git checkout $BRANCH
        fi

        if [[ $PATCHES = $YES ]] ; then
            # apply util custom patches
            git am $DIR/build/patches/*.patch
        fi
    popd

    if [[ $LINKS = $YES ]] ; then
        rm -f $DIR/../src/build
        ln -s $DOJO_DIR/util/build $DIR/../src/build
    fi
fi

popd # $DOJO_DIR
