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
	man			\
	$(NULL)

sbin_SCRIPTS =			\
	ipa-upgradeconfig	\
	$(NULL)

install-exec-local:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	chmod 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	mkdir -p $(DESTDIR)$(localstatedir)/cache/ipa/sessions
	chmod 700 $(DESTDIR)$(localstatedir)/cache/ipa/sessions

uninstall-local:
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa
	-rmdir $(DESTDIR)$(localstatedir)/cache/ipa/sessions
	-rmdir $(DESTDIR)$(localstatedir)/cache/ipa

EXTRA_DIST =			\
	ipa-server.spec		\
	COPYING			\
	AUTHORS			\
	INSTALL			\
	README			\
	HACKING			\
	NEWS			\
	ChangeLog		\
	$(sbin_SCRIPTS)		\
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
