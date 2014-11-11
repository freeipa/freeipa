MAINTAINERCLEANFILES = *~ Makefile.in
PLUGIN_COMMON_DIR = ../common
AM_CPPFLAGS =							\
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
	$(WARN_CFLAGS)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = libipa_otp_lasttoken.la
libipa_otp_lasttoken_la_SOURCES = ipa_otp_lasttoken.c
libipa_otp_lasttoken_la_LDFLAGS = -avoid-version -export-symbols ipa-otp-lasttoken.sym
libipa_otp_lasttoken_la_LIBADD =		\
	$(LDAP_LIBS)				\
	$(builddir)/../libotp/libotp.la
