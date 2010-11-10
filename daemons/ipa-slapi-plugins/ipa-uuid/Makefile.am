NULL =

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-I/usr/include/dirsrv					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(MOZLDAP_CFLAGS)					\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 		\
	libipa_uuid.la		\
	$(NULL)

libipa_uuid_la_SOURCES = 	\
	ipa_uuid.c		\
	$(NULL)

libipa_uuid_la_LDFLAGS = -avoid-version

libipa_uuid_la_LIBADD = 	\
	$(MOZLDAP_LIBS)		\
	$(UUID_LIBS)		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	uuid-conf.ldif		\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
