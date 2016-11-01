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

# Build DOJO builder, overwrites util/build/build.js. Cleans after itself.

# For first time usage, user have to have cloned Dojo reps. It's done by
# prepare-dojo.sh with --clone --util --dojo --checkout --patches options
# or just with --all option.


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create DOJO symbolic links to DOJO reps.
# Build of builder requires both original dojo and patched util repositories.
$DIR/prepare-dojo.sh --links --util --dojo

$DIR/clean.sh
$DIR/build.sh build

# Stop at error. We don't want to overwrite good builder with failed build.
if [[ $? != 0 ]] ; then
    echo "Build failed"
    exit 1
fi

# Compile and overwrite the builder
$DIR/compile.sh --release build --layer build/build --output $DIR/build/build.js
$DIR/clean.sh

# Delete DOJO symbolic links
rm -f $DIR/../src/dojo
rm -f $DIR/../src/build
