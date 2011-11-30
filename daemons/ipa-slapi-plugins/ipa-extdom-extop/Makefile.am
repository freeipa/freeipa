NULL =

PLUGIN_COMMON_DIR=../common

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I$(KRB5_UTIL_DIR)					\
	-I$(COMMON_BER_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(AM_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(WBCLIENT_CFLAGS)					\
	$(WARN_CFLAGS)						\
	$(SSSIDMAP_CFLAGS)					\
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
	$(WBCLIENT_LIBS)		\
	$(SSSIDMAP_LIBS)		\
	$(NULL)

if HAVE_CHECK
TESTS = extdom_tests
check_PROGRAMS = extdom_tests
endif

extdom_tests_SOURCES = 	\
	ipa_extdom_tests.c	\
	ipa_extdom_common.c	\
	$(NULL)
extdom_tests_CFLAGS = $(CHECK_CFLAGS)
extdom_tests_LDFLAGS =	\
	-rpath $(shell pkg-config --libs-only-L dirsrv | sed -e 's/-L//') \
	$(NULL)
extdom_tests_LDADD = 		\
	$(CHECK_LIBS)		\
	$(LDAP_LIBS)		\
	$(WBCLIENT_LIBS)	\
	$(DIRSRV_LIBS)		\
	$(SSSIDMAP_LIBS)	\
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
