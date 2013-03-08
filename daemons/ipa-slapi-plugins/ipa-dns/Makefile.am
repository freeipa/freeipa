NULL =

PLUGIN_COMMON_DIR=../common

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I/usr/include/dirsrv					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(AM_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 		\
	libipa_dns.la		\
	$(NULL)

libipa_dns_la_SOURCES = 	\
	ipa_dns.c		\
	$(NULL)

libipa_dns_la_LDFLAGS = -avoid-version

libipa_dns_la_LIBADD = 	\
	$(LDAP_LIBS)		\
	$(NULL)

EXTRA_DIST =			\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
