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
	$(SSSNSSIDMAP_CFLAGS)					\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_extdom_extop.la	\
	$(NULL)

libipa_extdom_extop_la_SOURCES = 	\
	ipa_extdom.h			\
	ipa_extdom_extop.c		\
	ipa_extdom_common.c		\
	back_extdom.h			\
	$(NULL)

libipa_extdom_extop_la_LDFLAGS = -avoid-version

libipa_extdom_extop_la_LIBADD = 	\
	$(LDAP_LIBS)			\
	$(SSSNSSIDMAP_LIBS)		\
	$(NULL)

# We have two backends for nss operations:
# (1) directly loading nss_sss.so.2
# (2) using timeout-enabled API from libsss_nss_idmap
# We prefer (2) if available
if USE_SSS_NSS_TIMEOUT
libipa_extdom_extop_la_SOURCES += back_extdom_sss_idmap.c
else
libipa_extdom_extop_la_SOURCES += back_extdom_nss_sss.c
endif


TESTS =
check_PROGRAMS =

if HAVE_CMOCKA
TESTS += extdom_cmocka_tests
check_PROGRAMS += extdom_cmocka_tests
endif

extdom_cmocka_tests_SOURCES = 		\
	ipa_extdom_cmocka_tests.c	\
	ipa_extdom_common.c		\
	back_extdom_nss_sss.c		\
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
	-ldl			\
	$(NULL)


appdir = $(IPA_DATA_DIR)
app_DATA =				\
	ipa-extdom-extop-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	test_data		\
	$(app_DATA)		\
	$(NULL)
