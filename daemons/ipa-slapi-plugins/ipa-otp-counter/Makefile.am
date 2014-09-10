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
plugin_LTLIBRARIES = libipa_otp_counter.la
libipa_otp_counter_la_SOURCES = berval.c berval.h ldapmod.c ldapmod.h ipa_otp_counter.c
libipa_otp_counter_la_LDFLAGS = -avoid-version -export-symbols ipa-otp-counter.sym
libipa_otp_counter_la_LIBADD = $(LDAP_LIBS)
