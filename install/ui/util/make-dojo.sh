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

# Build script for Dojo library

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$DIR/prepare-dojo.sh --links --dojo

$DIR/clean.sh
$DIR/build.sh dojo

# Stop at error. We don't want to overwrite good build with failed build.
if [[ $? != 0 ]] ; then
    echo "Build failed"
    exit 1
fi

$DIR/compile.sh --release dojo --layer dojo/dojo --output $DIR/../build/dojo/dojo.js
$DIR/clean.sh
