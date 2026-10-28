#!/bin/sh
autoreconf -i -f
./configure ${1+"$@"}
