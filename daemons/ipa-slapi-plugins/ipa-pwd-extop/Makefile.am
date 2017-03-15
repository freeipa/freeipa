NULL =

PLUGIN_COMMON_DIR = $(srcdir)/../common

AM_CPPFLAGS =							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I$(top_srcdir)/util					\
	-I$(top_srcdir)/asn1					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(DIRSRV_CFLAGS)					\
	$(CRYPTO_CFLAGS)					\
	$(LDAP_CFLAGS)						\
	$(KRB5_CFLAGS)						\
	$(NSPR_CFLAGS)						\
	$(NSS_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

AM_LDFLAGS = \
	$(CRYPTO_LIBS)	\
	$(KRB5_LIBS)	\
	$(LDAP_LIBS)	\
	$(NSPR_LIBS)	\
	$(NSS_LIBS)	\
	-avoid-version	\
	-export-symbols-regex ^ipapwd_init$

# Plugin Binary
plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = libipa_pwd_extop.la
libipa_pwd_extop_la_LIBADD  = \
	$(builddir)/../libotp/libotp.la \
	$(top_builddir)/asn1/libipaasn1.la	\
	$(top_builddir)/util/libutil.la		\
	$(NULL)
libipa_pwd_extop_la_SOURCES = 		\
	common.c			\
	encoding.c			\
	prepost.c			\
	ipa_pwd_extop.c			\
	ipapwd.h			\
	otpctrl.c			\
	otpctrl.h			\
	$(KRB5_UTIL_SRCS)		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	pwd-extop-conf.ldif	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_DATA)		\
	$(NULL)


