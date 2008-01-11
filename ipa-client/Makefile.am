# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL =

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(KRB5_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(SASL_CFLAGS)						\
	$(POPT_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

sbin_PROGRAMS =			\
	ipa-getkeytab		\
	$(NULL)

ipa_getkeytab_SOURCES =		\
	ipa-getkeytab.c		\
	$(NULL)

ipa_getkeytab_LDADD = 		\
	$(KRB5_LIBS)		\
	$(LDAP_LIBS)		\
	$(SASL_LIBS)		\
	$(POPT_LIBS)		\
	$(NULL)

SUBDIRS =			\
	firefox			\
	ipaclient		\
	ipa-install		\
	$(NULL)

EXTRA_DIST =			\
	ipa-client.spec		\
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
