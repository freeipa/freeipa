NULL =

PLUGIN_COMMON_DIR=../common

AM_CPPFLAGS =							\
	-I.							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I$(KRB5_UTIL_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(LDAP_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(SSSNSSIDMAP_CFLAGS)					\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_extdom_extop.la	\
	$(NULL)

libipa_extdom_extop_la_SOURCES = 	\
	ipa_extdom_extop.c		\
	ipa_extdom_common.c		\
	$(NULL)

libipa_extdom_extop_la_LDFLAGS = -avoid-version

libipa_extdom_extop_la_LIBADD = 	\
	$(LDAP_LIBS)			\
	$(SSSNSSIDMAP_LIBS)	\
	$(NULL)

TESTS =
check_PROGRAMS =

if HAVE_CMOCKA
if HAVE_NSS_WRAPPER
TESTS_ENVIRONMENT = . ./test_data/test_setup.sh;
TESTS += extdom_cmocka_tests
check_PROGRAMS += extdom_cmocka_tests
endif
endif

extdom_cmocka_tests_SOURCES = 		\
	ipa_extdom_cmocka_tests.c	\
	ipa_extdom_common.c		\
	$(NULL)
extdom_cmocka_tests_CFLAGS = $(CMOCKA_CFLAGS)
extdom_cmocka_tests_LDFLAGS = 	\
	-rpath $(shell pkg-config --libs-only-L dirsrv | sed -e 's/-L//') \
	$(NULL)
extdom_cmocka_tests_LDADD = 	\
	$(CMOCKA_LIBS)		\
	$(LDAP_LIBS)		\
	$(DIRSRV_LIBS)		\
	$(SSSNSSIDMAP_LIBS)	\
	$(NULL)


appdir = $(IPA_DATA_DIR)
app_DATA =				\
	ipa-extdom-extop-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
