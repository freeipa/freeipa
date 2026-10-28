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
plugin_LTLIBRARIES = 		\
	libipa_sidgen.la	\
	libipa_sidgen_task.la	\
	$(NULL)

libipa_sidgen_la_SOURCES = 	\
	ipa_sidgen.c		\
	ipa_sidgen_common.c	\
	$(NULL)

libipa_sidgen_la_LDFLAGS = -avoid-version

libipa_sidgen_la_LIBADD = 	\
	$(LDAP_LIBS)		\
	$(NULL)

libipa_sidgen_task_la_SOURCES = 	\
	ipa_sidgen_task.c		\
	ipa_sidgen_common.c		\
	$(NULL)

libipa_sidgen_task_la_LDFLAGS = -avoid-version

libipa_sidgen_task_la_LIBADD = 	\
	$(LDAP_LIBS)		\
	$(NULL)

noinst_HEADERS =	\
	ipa_sidgen.h

appdir = $(IPA_DATA_DIR)
app_DATA =				\
	ipa-sidgen-conf.ldif		\
	ipa-sidgen-task-conf.ldif	\
	ipa-sidgen-task-run.ldif	\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)
