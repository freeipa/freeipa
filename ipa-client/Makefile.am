# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL =

AM_CFLAGS = $(NULL)
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
		-Wcast-align -Werror-implicit-function-declaration \
		$(NULL)
endif
export AM_CFLAGS

KRB5_UTIL_DIR=../util
KRB5_UTIL_SRCS=$(KRB5_UTIL_DIR)/ipa_krb5.c

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-I$(KRB5_UTIL_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	-DLOCALEDIR=\""$(localedir)"\"				\
	$(AM_CFLAGS)						\
	$(KRB5_CFLAGS)						\
	$(OPENLDAP_CFLAGS)					\
	$(SASL_CFLAGS)						\
	$(POPT_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

sbin_PROGRAMS =			\
	ipa-getkeytab		\
	ipa-rmkeytab		\
	ipa-join		\
	$(NULL)

ipa_getkeytab_SOURCES =		\
	ipa-getkeytab.c		\
	ipa-client-common.c	\
	$(KRB5_UTIL_SRCS)	\
	$(NULL)

ipa_getkeytab_LDADD = 		\
	$(KRB5_LIBS)		\
	$(OPENLDAP_LIBS)	\
	$(SASL_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(NULL)

ipa_rmkeytab_SOURCES =		\
	ipa-rmkeytab.c		\
	ipa-client-common.c	\
	$(NULL)

ipa_rmkeytab_LDADD = 		\
	$(KRB5_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(NULL)

ipa_join_SOURCES =		\
	config.c		\
	ipa-client-common.c	\
	ipa-join.c		\
	$(NULL)

ipa_join_LDADD = 		\
	$(KRB5_LIBS)		\
	$(OPENLDAP_LIBS)	\
	$(SASL_LIBS)		\
	$(CURL_LIBS)		\
	$(XMLRPC_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(NULL)

SUBDIRS =			\
	firefox			\
	ipaclient		\
	ipa-install		\
	man			\
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
	COPYING			\
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
	version.m4		\
	ipa-client.spec		\
	py-compile		\
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
