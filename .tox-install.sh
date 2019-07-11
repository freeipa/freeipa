#!/bin/bash
set -ex

FLAVOR="$1"
ENVPYTHON="$(realpath "$2")"
ENVSITEPACKAGESDIR="$(realpath "$3")"
ENVDIR="$4"
# 4...end are package requirements
shift 4

TOXINIDIR="$(cd "$(dirname "$0")" && pwd)"

# sanity checks
if [ ! -x "${ENVPYTHON}" ]; then
    echo "${ENVPYTHON}: no such executable"
    exit 1
fi

if [ ! -d "${ENVSITEPACKAGESDIR}" ]; then
    echo "${ENVSITEPACKAGESDIR}: no such directory"
    exit 2
fi

if [ ! -f "${TOXINIDIR}/tox.ini" ]; then
    echo "${TOXINIDIR}: no such directory"
    exit 3
fi

if [ ! -d "${ENVDIR}" ]; then
    echo "${ENVDIR}: no such directory"
    exit 4
fi

# https://pip.pypa.io/en/stable/user_guide/#environment-variables
export PIP_CACHE_DIR="${TOXINIDIR}/.tox/cache"
mkdir -p "${PIP_CACHE_DIR}"

# /tmp could be mounted with noexec option.
# pip checks if path is executable and if not then doesn't set such
# permission bits
export PIP_BUILD="${ENVDIR}/pip_build"
rm -rf "${PIP_BUILD}"

DISTBUNDLE="${TOXINIDIR}/dist/bundle"
mkdir -p "${DISTBUNDLE}"

DISTPYPI="${TOXINIDIR}/dist/pypi"
mkdir -p "${DISTPYPI}"

# create configure
pushd "${TOXINIDIR}"
if [ ! -f "configure" ]; then
    autoreconf -i -f
fi
# (re)create Makefile
./configure --disable-server
popd

case $FLAVOR in
wheel_bundle)
    # copy pylint plugin
    cp "${TOXINIDIR}/pylint_plugins.py" "${ENVSITEPACKAGESDIR}"

    # build packages and bundles
    make -C "${TOXINIDIR}" \
        wheel_bundle \
        PYTHON="${ENVPYTHON}" \
        IPA_EXTRA_WHEELS="$*"

    # chdir to prevent local .egg-info from messing up pip
    pushd "${ENVSITEPACKAGESDIR}"

    # Install packages with dist/bundle/ as extra source for wheels while ignoring
    # upstream Python Package Index.
    $ENVPYTHON -m pip install \
        --no-index \
        --disable-pip-version-check \
        --constraint "${TOXINIDIR}/.wheelconstraints" \
        --find-links "${DISTBUNDLE}" \
        $@

    popd
    ;;
pypi_packages)
    # build packages and bundles
    make -C "${TOXINIDIR}" \
        pypi_packages \
        PYTHON="${ENVPYTHON}"

    # chdir to prevent local .egg-info from messing up pip
    pushd "${ENVSITEPACKAGESDIR}"

    # Install packages from dist/pypi
    $ENVPYTHON -m pip install \
        --disable-pip-version-check \
        --constraint "${TOXINIDIR}/.wheelconstraints" \
        --find-links "${DISTPYPI}" \
        $@

    popd
    ;;
*)
    echo "Unknown install flavor $FLAVOR"
    exit 1
    ;;
esac
