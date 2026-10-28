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
	$(LDAP_CFLAGS)					\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_winsync.la		\
	$(NULL)

libipa_winsync_la_SOURCES = 		\
	ipa-winsync.c			\
	ipa-winsync.h			\
	ipa-winsync-config.c			\
	$(NULL)

libipa_winsync_la_LDFLAGS = -avoid-version

#libipa_winsync_la_LIBADD = 		\
#	$(LDAP_LIBS)			\
#	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-winsync-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_DATA)		\
	$(NULL)
