NULL =
SAMBA40EXTRA_LIBS = $(SAMBA40EXTRA_LIBPATH)	\
			-lsmbldap		\
			-lpdb			\
			-lsmbconf		\
			$(NULL)

KRB5_UTIL_DIR=../../util
KRB5_UTIL_SRCS=$(KRB5_UTIL_DIR)/ipa_krb5.c $(KRB5_UTIL_DIR)/ipa_pwd_ntlm.c

INCLUDES =						\
	-I.						\
	-I$(srcdir)					\
	-I/usr/include/samba-4.0			\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\"			\
	-DLIBDIR=\""$(libdir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DDATADIR=\""$(datadir)"\"			\
	-DLDAPIDIR=\""$(localstatedir)/run"\"		\
	-DHAVE_LDAP					\
	-I $(KRB5_UTIL_DIR)				\
	$(AM_CFLAGS)					\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)					\
	$(WARN_CFLAGS)					\
	$(TALLOC_CFLAGS)				\
	$(SAMBAUTIL_CFLAGS)				\
	$(NDR_CFLAGS)					\
	$(SSSIDMAP_CFLAGS)				\
	$(NULL)

plugindir = $(libdir)/samba/pdb
plugin_LTLIBRARIES = 		\
	ipasam.la		\
	$(NULL)

ipasam_la_SOURCES = 		\
	ipa_sam.c		\
	$(KRB5_UTIL_SRCS)	\
	$(NULL)

ipasam_la_LDFLAGS = 		\
	-avoid-version		\
	-module			\
	$(NULL)

ipasam_la_LIBADD = 		\
	$(LDAP_LIBS)		\
	$(KRB5_LIBS)		\
	$(TALLOC_LIBS)		\
	$(SSL_LIBS)		\
	$(SAMBAUTIL_LIBS)	\
	$(NDR_LIBS)		\
	$(SAMBA40EXTRA_LIBS)	\
	$(SSSIDMAP_LIBS)	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	ipa_sam.h		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
