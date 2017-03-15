PLUGIN_COMMON_DIR = $(srcdir)/../common
AM_CPPFLAGS =							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(AM_CFLAGS)						\
	$(DIRSRV_CFLAGS)					\
	$(LDAP_CFLAGS)						\
	$(WARN_CFLAGS)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = libipa_otp_lasttoken.la
libipa_otp_lasttoken_la_SOURCES = ipa_otp_lasttoken.c ipa-otp-lasttoken.sym
libipa_otp_lasttoken_la_LDFLAGS = -avoid-version -export-symbols $(srcdir)/ipa-otp-lasttoken.sym
libipa_otp_lasttoken_la_LIBADD =		\
	$(LDAP_LIBS)				\
	$(builddir)/../libotp/libotp.la
