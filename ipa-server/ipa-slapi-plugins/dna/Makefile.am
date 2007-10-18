NULL =

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(MOZLDAP_CFLAGS)					\
	$(LDAP_CFLAGS)						\
	$(KRB5_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa-dna-plugin.la		\
	$(NULL)

libipa_dna_plugin_la_SOURCES = 		\
	dna.c				\
	$(NULL)

libipa_dna_plugin_la_LDFLAGS = -avoid-version

libipa_dna_plugin_la_LIBADD = 		\
	$(MOZLDAP_LIBS)			\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	dna-conf.ldif		\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
