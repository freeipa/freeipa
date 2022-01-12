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
	-I$(top_srcdir)/util						\
	$(DIRSRV_CFLAGS)					\
	$(LDAP_CFLAGS)					\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 		\
	libipa_graceperiod.la		\
	$(NULL)

libipa_graceperiod_la_SOURCES = 	\
	ipa_graceperiod.c		\
	$(NULL)

libipa_graceperiod_la_LDFLAGS = -avoid-version

libipa_graceperiod_la_LIBADD = 	\
	$(LDAP_LIBS)		\
	$(top_builddir)/util/libutil.la		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	graceperiod-conf.ldif		\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)
