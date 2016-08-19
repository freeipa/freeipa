# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

SUBDIRS = systemd tmpfilesd

dist_sysconfenv_DATA = 		\
	ipa-dnskeysyncd		\
	ipa-ods-exporter

CLEANFILES = $(nodist_sysconfenv_DATA)

%: %.in Makefile
	sed -e 's|@localstatedir[@]|$(localstatedir)|g' '$(srcdir)/$@.in' >$@
