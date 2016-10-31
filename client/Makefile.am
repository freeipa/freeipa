# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7 subdir-objects

NULL =

AM_CFLAGS = $(NULL)
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
		-Wcast-align -Werror-implicit-function-declaration \
		$(NULL)
endif
export AM_CFLAGS

IPA_CONF_FILE=$(sysconfdir)/ipa/default.conf

AM_CPPFLAGS =							\
	-I$(srcdir)						\
	-I$(top_srcdir)/util					\
	-I$(top_srcdir)/asn1					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	-DLOCALEDIR=\""$(localedir)"\"				\
	-DIPACONFFILE=\""$(IPA_CONF_FILE)"\"			\
	$(KRB5_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(SASL_CFLAGS)						\
	$(POPT_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(INI_CFLAGS)						\
	$(NULL)

sbin_PROGRAMS =			\
	ipa-getkeytab		\
	ipa-rmkeytab		\
	ipa-join		\
	$(NULL)

sbin_SCRIPTS =			\
	ipa-client-install	\
	ipa-client-automount	\
	ipa-certupdate		\
	$(NULL)

ipa_getkeytab_SOURCES =		\
	ipa-getkeytab.c		\
	ipa-client-common.c	\
	$(KRB5_UTIL_SRCS)	\
	$(NULL)

ipa_getkeytab_LDADD = 		\
	$(top_builddir)/asn1/libipaasn1.la	\
	$(top_builddir)/util/libutil.la	\
	$(KRB5_LIBS)		\
	$(LDAP_LIBS)		\
	$(SASL_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(INI_LIBS)		\
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
	$(LDAP_LIBS)		\
	$(SASL_LIBS)		\
	$(XMLRPC_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(NULL)

SUBDIRS =			\
	man			\
	$(NULL)

EXTRA_DIST =			\
	$(sbin_SCRIPTS)		\
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
	$(NULL)

