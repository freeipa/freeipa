AUTOMAKE_OPTIONS = 1.7 subdir-objects

NULL =


AM_CPPFLAGS =						\
	-I$(srcdir)					\
	-I$(top_srcdir)/util				\
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
	$(SSSCERTMAP_CFLAGS)				\
	$(NULL)

plugindir = $(libdir)/krb5/plugins/kdb
plugin_LTLIBRARIES = 		\
	ipadb.la		\
	$(NULL)

ipadb_la_SOURCES = 		\
	ipa_kdb.c		\
	ipa_kdb.h		\
	ipa_kdb_common.c	\
	ipa_kdb_mkey.c		\
	ipa_kdb_passwords.c	\
	ipa_kdb_principals.c	\
	ipa_kdb_pwdpolicy.c	\
	ipa_kdb_mspac.c		\
	ipa_kdb_mspac_private.h	\
	ipa_kdb_delegation.c	\
	ipa_kdb_audit_as.c	\
	$(NULL)

dist_noinst_DATA = ipa_kdb.exports

if BUILD_IPA_CERTAUTH_PLUGIN
ipadb_la_SOURCES += ipa_kdb_certauth.c
endif

if BUILD_IPA_KDCPOLICY_PLUGIN
ipadb_la_SOURCES += ipa_kdb_kdcpolicy.c
endif

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
	$(SSSCERTMAP_LIBS)	\
	$(top_builddir)/util/libutil.la	\
	$(NULL)

if HAVE_CMOCKA
TESTS_ENVIRONMENT = . $(srcdir)/tests/test_setup.sh;
dist_ipa_kdb_tests_SOURCES = tests/test_setup.sh
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

if BUILD_IPA_CERTAUTH_PLUGIN
ipa_kdb_tests_SOURCES += ipa_kdb_certauth.c
endif

if BUILD_IPA_KDCPOLICY_PLUGIN
ipa_kdb_tests_SOURCES += ipa_kdb_kdcpolicy.c
endif

ipa_kdb_tests_CFLAGS = $(CMOCKA_CFLAGS)
ipa_kdb_tests_LDADD =          \
       $(CMOCKA_LIBS)          \
       $(KRB5_LIBS)            \
       $(LDAP_LIBS)            \
       $(NDRPAC_LIBS)          \
       $(UNISTRING_LIBS)       \
       $(NSS_LIBS)             \
       $(SSSCERTMAP_LIBS)      \
       $(top_builddir)/util/libutil.la	\
       -lkdb5                  \
       -lsss_idmap             \
       $(NULL)

clean-local:
	rm -f tests/.dirstamp

EXTRA_DIST =			\
	README			\
	README.s4u2proxy.txt	\
	$(NULL)
