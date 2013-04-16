NULL =

MAINTAINERCLEANFILES = *~ Makefile.in
PLUGIN_COMMON_DIR = ../common
KRB5_UTIL_DIR = ../../../util
KRB5_UTIL_SRCS = $(KRB5_UTIL_DIR)/ipa_krb5.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd_ntlm.c

AM_CPPFLAGS =							\
	-I.							\
	-I$(srcdir)						\
	-I$(PLUGIN_COMMON_DIR)					\
	-I$(KRB5_UTIL_DIR)					\
	-I$(COMMON_BER_DIR)					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(AM_CFLAGS)						\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)						\
	$(SSL_CFLAGS)						\
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

# OTP Convenience Library and Tests
noinst_LTLIBRARIES = libotp.la
libotp_la_SOURCES = otp.c
check_PROGRAMS = t_hotp t_totp
t_hotp_LDADD = libotp.la
t_totp_LDADD = libotp.la
TESTS = $(check_PROGRAMS)

# Plugin Binary
plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = libipa_pwd_extop.la
libipa_pwd_extop_la_LIBADD  = libotp.la
libipa_pwd_extop_la_SOURCES = 		\
	auth.c				\
	common.c			\
	encoding.c			\
	prepost.c			\
	ipa_pwd_extop.c			\
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


