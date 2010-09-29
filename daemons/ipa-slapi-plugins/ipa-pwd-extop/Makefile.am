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
	$(KRB5_CFLAGS)						\
	$(SSL_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_pwd_extop.la		\
	$(NULL)

libipa_pwd_extop_la_SOURCES = 		\
	ipapwd_common.c			\
	ipapwd_encoding.c		\
	ipapwd_prepost.c		\
	ipa_pwd_extop.c			\
	$(NULL)

libipa_pwd_extop_la_LDFLAGS = -avoid-version

libipa_pwd_extop_la_LIBADD = 		\
	$(KRB5_LIBS)			\
	$(SSL_LIBS)			\
	$(MOZLDAP_LIBS)			\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	pwd-extop-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
