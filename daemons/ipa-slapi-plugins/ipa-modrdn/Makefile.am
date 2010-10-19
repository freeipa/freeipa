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
	libipa_modrdn.la		\
	$(NULL)

libipa_modrdn_la_SOURCES = 	\
	ipa_modrdn.c		\
	$(NULL)

libipa_modrdn_la_LDFLAGS = -avoid-version

libipa_modrdn_la_LIBADD = 	\
	$(MOZLDAP_LIBS)		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	modrdn-conf.ldif		\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
