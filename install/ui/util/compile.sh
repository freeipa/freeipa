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
     compile.sh - Compiles layer file of Dojo build using uglify.js.
                  Deletes all other files.

SYNOPSIS
     path/to/compile.sh [--help] --release RELEASE --layer NAME/NAME

DESCRIPTION
     Compiles layer file of Dojo build output using uglify.js.
     Deletes all other files.

OPTIONS
     --help         print the help message

     -r
     --release      build release name

     -l
     --layer        layer name

     -o
     --output       output JavaScript file
__EOF__
}

if [ "$#" = "0" ] ; then
    usage
    exit 1
fi

args=`getopt -u -l help,release:,layer:,output: l:r:o: $*`

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
        --release | -r)
            shift;
            RELEASE=$1
            shift;
            ;;
        --layer | -l)
            shift;
            LAYER=$1
            shift;
            ;;
        --output | -o)
            shift;
            OUTPUT_FILE=$1
            shift;
            ;;
        *)
            ;;
    esac
done

if [[ $HELP ]] ; then
    usage
    exit 0
fi

if [[ ! $RELEASE ]] || [[ ! $LAYER ]] ; then
    echo 'Wrong input \n use --help for instructions'
    exit 1
fi

if [[ ! $OUTPUT_FILE ]] ; then
    OUTPUT_FILE=$RDIR/$RELEASE/$LAYER.js
fi

# compile using uglifyjs
echo "Minimizing: $RDIR/$RELEASE/$LAYER.js"
echo "Target file: $OUTPUT_FILE"
uglifyjs $RDIR/$RELEASE/$LAYER.js > $OUTPUT_FILE
