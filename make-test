#!/bin/bash
set -ex

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PYTHONPATH=$SCRIPTDIR:$PYTHONPATH py.test --confcutdir="$SCRIPTDIR" "$@"
