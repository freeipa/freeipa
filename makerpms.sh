#!/bin/bash
set -o errexit

pushd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

test ! -x "configure" && autoreconf -i
# run configure with the same parameters as RPM build
# this makes it easy to tweak files locally and use make install
test ! -f "Makefile" && ./configure --enable-silent-rules \
	--host=$(rpm -E %{_host}) \
	--build=$(rpm -E %{_build}) \
	--program-prefix=$(rpm -E %{?_program_prefix}) \
	--prefix=$(rpm -E %{_prefix}) \
	--exec-prefix=$(rpm -E %{_exec_prefix}) \
	--bindir=$(rpm -E %{_bindir}) \
	--sbindir=$(rpm -E %{_sbindir}) \
	--sysconfdir=$(rpm -E %{_sysconfdir}) \
	--datadir=$(rpm -E %{_datadir}) \
	--includedir=$(rpm -E %{_includedir}) \
	--libdir=$(rpm -E %{_libdir}) \
	--libexecdir=$(rpm -E %{_libexecdir}) \
	--localstatedir=$(rpm -E %{_localstatedir}) \
	--sharedstatedir=$(rpm -E %{_sharedstatedir}) \
	--mandir=$(rpm -E %{_mandir}) \
	--infodir=$(rpm -E %{_infodir}) \
	"$@"
make rpms

# Workaround to ignore re-generated *.po files in git repo
# See https://pagure.io/freeipa/issue/6605
git checkout po/*.po ||:

popd
