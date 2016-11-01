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

# Build script for FreeIPA Web UI

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
IPA_DIR=$DIR/../build/freeipa

if [ ! -d $IPA_DIR ] ; then
    mkdir $IPA_DIR
fi

$DIR/clean.sh
$DIR/build.sh webui
# don't stop at error. Some dependency errors are expected.
$DIR/compile.sh --release lib --layer freeipa/core --output $IPA_DIR/core.js
$DIR/compile.sh --release lib --layer freeipa/app --output $IPA_DIR/app.js
$DIR/clean.sh
