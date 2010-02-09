#!/bin/sh

# automake demands these files exist when run in gnu mode which is the default,
# automake can be run in foreign mode to avoid failing on the absence of these
# files, but unfortunately there is no way to pass the --foreign flag to
# automake when run from autoreconf.
for f in NEWS README AUTHORS ChangeLog; do
    if [ ! -e $f ]; then
        touch $f
    fi
done

autoreconf -i
./configure ${1+"$@"}
