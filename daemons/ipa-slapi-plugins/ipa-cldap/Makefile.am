NULL =

PLUGIN_COMMON_DIR=../common

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I$(COMMON_BER_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(AM_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NDRNBT_CFLAGS)					\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_cldap.la			\
	$(NULL)

libipa_cldap_la_SOURCES = 		\
	ipa_cldap_netlogon.c		\
	ipa_cldap_worker.c		\
	ipa_cldap.c			\
	$(NULL)

libipa_cldap_la_LDFLAGS = -avoid-version

libipa_cldap_la_LIBADD = 		\
	$(LDAP_LIBS)			\
	$(NDRNBT_LIBS)			\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-cldap-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
