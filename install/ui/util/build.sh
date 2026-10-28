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

# Build script for FreeIPA Web UI
set -o errexit

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

profile=$1

if [[ ! $profile ]] ; then
    echo 'No profile set'
    echo 'Usage: build.sh PROFILE_NAME'
    exit 1
fi

node $DIR/build/build.js load=build profile=$DIR/../src/$profile.profile.js
exit $?
