NULL =

INCLUDES =						\
	-I.						\
	-I$(srcdir)					\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\"			\
	-DLIBDIR=\""$(libdir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DDATADIR=\""$(datadir)"\"			\
	$(AM_CFLAGS)					\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)					\
	$(SSL_CFLAGS)					\
	$(WARN_CFLAGS)					\
	$(NULL)

plugindir = $(libdir)/krb5/plugins/kdb
plugin_LTLIBRARIES = 		\
	ipadb.la		\
	$(NULL)

ipadb_la_SOURCES = 		\
	ipa_kdb.c		\
	$(NULL)

ipadb_la_LDFLAGS = 		\
	-avoid-version 		\
	-module			\
	-Wl,--version-script,$(srcdir)/ipa_kdb.exports

ipadb_la_LIBADD = 		\
	$(KRB5_LIBS)		\
	$(SSL_LIBS)		\
	$(LDAP_LIBS)		\
	$(NULL)

dist_noinst_DATA = ipa_kdb.exports

EXTRA_DIST =			\
	README			\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
