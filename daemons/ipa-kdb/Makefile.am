AUTOMAKE_OPTIONS = 1.7 subdir-objects

NULL =

KRB5_UTIL_DIR = ../../util
IPA_UTIL_DIR = ../../../util

AM_CPPFLAGS =						\
	-I.						\
	-I$(srcdir)					\
	-I$(KRB5_UTIL_DIR)				\
	-I$(IPA_UTIL_DIR)				\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\"			\
	-DLIBDIR=\""$(libdir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DDATADIR=\""$(datadir)"\"			\
	-DLDAPIDIR=\""$(localstatedir)/run"\"		\
	$(AM_CFLAGS)					\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)					\
	$(WARN_CFLAGS)					\
	$(NDRPAC_CFLAGS)				\
	$(NSS_CFLAGS)					\
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
	ipa_kdb_mspac.c		\
	ipa_kdb_delegation.c	\
	ipa_kdb_audit_as.c	\
	$(NULL)

ipadb_la_LDFLAGS = 		\
	-avoid-version 		\
	-module			\
	-Wl,--version-script,$(srcdir)/ipa_kdb.exports

ipadb_la_LIBADD = 		\
	$(KRB5_LIBS)		\
	$(LDAP_LIBS)		\
	$(NDRPAC_LIBS)		\
	$(UNISTRING_LIBS)	\
	$(NSS_LIBS)             \
	$(KRB5_UTIL_DIR)/libutil.la	\
	$(NULL)

if HAVE_CMOCKA
TESTS = ipa_kdb_tests
check_PROGRAMS = ipa_kdb_tests
endif

ipa_kdb_tests_SOURCES =        \
       tests/ipa_kdb_tests.c   \
       ipa_kdb.c               \
       ipa_kdb_common.c        \
       ipa_kdb_mkey.c          \
       ipa_kdb_passwords.c     \
       ipa_kdb_principals.c    \
       ipa_kdb_pwdpolicy.c     \
       ipa_kdb_mspac.c         \
       ipa_kdb_delegation.c    \
       ipa_kdb_audit_as.c      \
       $(NULL)
ipa_kdb_tests_CFLAGS = $(CMOCKA_CFLAGS)
ipa_kdb_tests_LDADD =          \
       $(CMOCKA_LIBS)          \
       $(KRB5_LIBS)            \
       $(LDAP_LIBS)            \
       $(NDRPAC_LIBS)          \
       $(UNISTRING_LIBS)       \
       $(NSS_LIBS)             \
       $(KRB5_UTIL_DIR)/libutil.la	\
       -lkdb5                  \
       -lsss_idmap             \
       $(NULL)

dist_noinst_DATA = ipa_kdb.exports

EXTRA_DIST =			\
	README			\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
