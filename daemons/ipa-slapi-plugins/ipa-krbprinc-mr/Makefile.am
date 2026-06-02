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
	$(KRB5_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 		\
	libipa_krbprinc_mr.la	\
	$(NULL)

libipa_krbprinc_mr_la_SOURCES = 	\
	ipa_krbprinc_mr.c		\
	$(NULL)

libipa_krbprinc_mr_la_LDFLAGS = -avoid-version

libipa_krbprinc_mr_la_LIBADD = 	\
	$(KRB5_LIBS)			\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-krbprinc-mr-conf.ldif \
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)
