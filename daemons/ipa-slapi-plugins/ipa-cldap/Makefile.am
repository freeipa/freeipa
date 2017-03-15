NULL =

PLUGIN_COMMON_DIR = $(srcdir)/../common

AM_CPPFLAGS =							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(DIRSRV_CFLAGS)					\
	$(LDAP_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NDRNBT_CFLAGS)					\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_cldap.la			\
	$(NULL)

libipa_cldap_la_SOURCES = 		\
	ipa_cldap_netlogon.c		\
	ipa_cldap_worker.c		\
	ipa_cldap.c			\
	ipa_cldap.h			\
	$(NULL)

libipa_cldap_la_LDFLAGS = -avoid-version

libipa_cldap_la_LIBADD = 		\
	$(LDAP_LIBS)			\
	$(NDRNBT_LIBS)			\
	$(NULL)

if HAVE_CMOCKA
TESTS = ipa_cldap_tests
check_PROGRAMS = ipa_cldap_tests
endif

ipa_cldap_tests_SOURCES =	\
	ipa_cldap_tests.c	\
	ipa_cldap_netlogon.c	\
	$(NULL)
ipa_cldap_tests_CFLAGS = $(CMOCKA_FLAGS)
ipa_cldap_tests_LDFLAGS =	\
	-rpath $(shell pkg-config --libs-only-L dirsrv | sed -e 's/-L//')	\
	$(NULL)
ipa_cldap_tests_LDADD =	\
	$(CMOCKA_LIBS)	\
	$(NDRNBT_LIBS)	\
	$(DIRSRV_LIBS)	\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-cldap-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)
