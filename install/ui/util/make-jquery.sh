#!/bin/bash -eu

if [ $# -ne 1 ]; then
    echo 'The script requires exactly one argument (a jQuery version):'
    echo
    echo '  $ ./make-jquery.sh 3.4.1'
    echo
    exit 1
fi

WD=$(realpath $(dirname "${BASH_SOURCE[0]}"))
JQUERY_VERSION=$1

# Clone jQuery and apply patches
JQUERY_CLONE=$(mktemp -d)
git clone -b ${JQUERY_VERSION} --depth 1 https://github.com/jquery/jquery.git $JQUERY_CLONE
pushd $JQUERY_CLONE
git am ${WD}/jquery-patches/${JQUERY_VERSION}/*

# Build jQuery
npm install
npm run-script build

# Replace the project version of jQuery with the built one
cp -fv dist/jquery.min.js ${WD}/../src/libs/jquery.js

# Clean up
popd
rm -rf $JQUERY_CLONE
