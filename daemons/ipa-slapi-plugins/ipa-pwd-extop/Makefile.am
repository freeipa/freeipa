NULL =

PLUGIN_COMMON_DIR=../common
KRB5_UTIL_DIR= ../../../util
KRB5_UTIL_SRCS = $(KRB5_UTIL_DIR)/ipa_krb5.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd.c \
		 $(KRB5_UTIL_DIR)/ipa_pwd_ntlm.c

INCLUDES =							\
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

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = 			\
	libipa_pwd_extop.la		\
	$(NULL)

libipa_pwd_extop_la_SOURCES = 		\
	ipapwd_common.c			\
	ipapwd_encoding.c		\
	ipapwd_prepost.c		\
	ipa_pwd_extop.c			\
	$(KRB5_UTIL_SRCS)		\
	$(NULL)

libipa_pwd_extop_la_LDFLAGS = -avoid-version

libipa_pwd_extop_la_LIBADD = 		\
	$(KRB5_LIBS)			\
	$(SSL_LIBS)			\
	$(LDAP_LIBS)			\
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
