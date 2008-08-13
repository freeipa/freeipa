NULL =

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_winsync.la		\
	$(NULL)

libipa_winsync_la_SOURCES = 		\
	ipa_winsync.c			\
	$(NULL)

libipa_winsync_la_LDFLAGS = -avoid-version

#libipa_winsync_la_LIBADD = 		\
#	$(KRB5_LIBS)			\
#	$(SSL_LIBS)			\
#	$(MOZLDAP_LIBS)			\
#	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-winsync-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
