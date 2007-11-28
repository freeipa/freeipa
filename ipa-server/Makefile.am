# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL =

SUBDIRS =			\
	ipa-gui			\
	ipa-install		\
	ipa-kpasswd		\
	ipaserver		\
	ipa-slapi-plugins	\
	xmlrpc-server		\
	ipa-keytab-util		\
	$(NULL)

EXTRA_DIST =			\
	freeipa-server.spec	\
	COPYING			\
	AUTHORS			\
	INSTALL			\
	README			\
	HACKING			\
	NEWS			\
	ChangeLog		\
	$(NULL)

DISTCLEANFILES =		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	intltool-*.in		\
	compile			\
	configure		\
	INSTALL			\
	install-sh		\
	missing			\
	mkinstalldirs		\
	config.guess		\
	ltmain.sh		\
	config.sub		\
	depcomp			\
	Makefile.in		\
	config.h.*		\
	aclocal.m4		\
	$(NULL)

# Creating ChangeLog from hg log (taken from cairo/Makefile.am):

ChangeLog: $(srcdir)/ChangeLog

$(srcdir)/ChangeLog:
	@if test -d "$(srcdir)/../.hg"; then \
	  (cd "$(srcdir)" && \
	  ./missing --run hg log --verbose) | fmt --split-only > $@.tmp \
	  && mv -f $@.tmp $@ \
	  || ($(RM) $@.tmp; \
	      echo Failed to generate ChangeLog, your ChangeLog may be outdated >&2; \
	      (test -f $@ || echo hg log is required to generate this file >> $@)); \
	else \
	  test -f $@ || \
	  (echo A hg checkout and hg -log is required to generate ChangeLog >&2 && \
	  echo A hg checkout and hg log is required to generate this file >> $@); \
	fi

.PHONY: ChangeLog $(srcdir)/ChangeLog
