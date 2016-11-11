NULL =
LIBPDB_NAME = @LIBPDB_NAME@
SAMBA40EXTRA_LIBS = $(SAMBA40EXTRA_LIBPATH)	\
			-lsmbldap		\
			-l$(LIBPDB_NAME)			\
			-lsmbconf		\
			$(NULL)

AM_CPPFLAGS =						\
	-I$(srcdir)					\
	-I$(top_srcdir)/asn1				\
	-I/usr/include/samba-4.0			\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\"			\
	-DLIBDIR=\""$(libdir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DDATADIR=\""$(datadir)"\"			\
	-DLDAPIDIR=\""$(localstatedir)/run"\"		\
	-DHAVE_LDAP					\
	-I$(top_srcdir)/util				\
	$(CRYPTO_CFLAGS)				\
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
	$(CRYPTO_LIBS)		\
	$(LDAP_LIBS)		\
	$(KRB5_LIBS)		\
	$(TALLOC_LIBS)		\
	$(SAMBAUTIL_LIBS)	\
	$(NDR_LIBS)		\
	$(SAMBA40EXTRA_LIBS)	\
	$(SSSIDMAP_LIBS)	\
	$(top_builddir)/asn1/libipaasn1.la  \
	$(top_builddir)/util/libutil.la	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	ipa_sam.h		\
	$(NULL)
