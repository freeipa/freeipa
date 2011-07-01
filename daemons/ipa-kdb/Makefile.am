NULL =

KRB5_UTIL_DIR = ../../util
KRB5_UTIL_SRCS = $(KRB5_UTIL_DIR)/ipa_krb5.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd.c

INCLUDES =						\
	-I.						\
	-I$(srcdir)					\
	-I$(KRB5_UTIL_DIR)				\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\"			\
	-DLIBDIR=\""$(libdir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DDATADIR=\""$(datadir)"\"			\
	-DLDAPIDIR=\""$(localstatedir)/run"\"		\
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
	ipa_kdb_common.c	\
	ipa_kdb_mkey.c		\
	ipa_kdb_passwords.c	\
	ipa_kdb_principals.c	\
	ipa_kdb_pwdpolicy.c	\
	$(KRB5_UTIL_SRCS)	\
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
