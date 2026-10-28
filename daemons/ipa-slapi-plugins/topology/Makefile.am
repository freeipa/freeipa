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
	libtopology.la		\
	$(NULL)

libtopology_la_SOURCES = 		\
	topology.h	\
	topology_agmt.c	\
	topology_init.c	\
	topology_cfg.c	\
	topology_post.c	\
	topology_pre.c	\
	topology_util.c	\
	$(NULL)

libtopology_la_LDFLAGS = -avoid-version

#libtopology_la_LIBADD = 		\
#	$(LDAP_LIBS)			\
#	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-topology-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)
