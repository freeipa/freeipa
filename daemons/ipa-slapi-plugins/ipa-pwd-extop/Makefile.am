NULL =

MAINTAINERCLEANFILES = *~ Makefile.in
PLUGIN_COMMON_DIR = ../common
KRB5_UTIL_DIR = ../../../util
KRB5_UTIL_SRCS = $(KRB5_UTIL_DIR)/ipa_krb5.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd_ntlm.c
ASN1_UTIL_DIR=../../../asn1

AM_CPPFLAGS =							\
	-I.							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I$(KRB5_UTIL_DIR)					\
	-I$(ASN1_UTIL_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)						\
	$(SSL_CFLAGS)						\
	$(NSS_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

AM_LDFLAGS = \
	$(KRB5_LIBS)	\
	$(SSL_LIBS)	\
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
	$(ASN1_UTIL_DIR)/libipaasn1.la  \
	$(NULL)
libipa_pwd_extop_la_SOURCES = 		\
	common.c			\
	encoding.c			\
	prepost.c			\
	ipa_pwd_extop.c			\
	syncreq.c			\
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


