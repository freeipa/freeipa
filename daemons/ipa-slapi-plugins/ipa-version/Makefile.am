NULL =

PLUGIN_COMMON_DIR = $(srcdir)/../common

AM_CPPFLAGS =							\
	-I$(srcdir)						\
	-I$(top_builddir)/daemons/				\
	-I$(PLUGIN_COMMON_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(DIRSRV_CFLAGS)					\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_repl_version.la	\
	$(NULL)

libipa_repl_version_la_SOURCES = 	\
	ipa_repl_version.c		\
	$(NULL)

libipa_repl_version_la_LDFLAGS = -avoid-version

libipa_repl_version_la_LIBADD = 	\
	$(LDAP_LIBS)			\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	version-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)
