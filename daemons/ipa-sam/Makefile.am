NULL =
SAMBA40EXTRA_LIBS = $(SAMBA40EXTRA_LIBPATH)	\
			-lsmbldap		\
			-lcliauth		\
			-lpdb			\
			-lsecurity		\
			-lsmbconf		\
			$(NULL)

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
	$(AM_CFLAGS)					\
	$(LDAP_CFLAGS)					\
	$(KRB5_CFLAGS)					\
	$(WARN_CFLAGS)					\
	$(TALLOC_CFLAGS)				\
	$(SAMBAUTIL_CFLAGS)				\
	$(NDR_CFLAGS)					\
	$(NULL)

plugindir = $(libdir)/samba/pdb
plugin_LTLIBRARIES = 		\
	ipasam.la		\
	$(NULL)

ipasam_la_SOURCES = 		\
	ipa_sam.c		\
	$(NULL)

ipasam_la_LDFLAGS = 		\
	-avoid-version		\
	-module			\
	$(NULL)

ipasam_la_LIBADD = 		\
	$(LDAP_LIBS)		\
	$(TALLOC_LIBS)		\
	$(SAMBAUTIL_LIBS)	\
	$(NDR_LIBS)		\
	$(SAMBA40EXTRA_LIBS)	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	ipa_sam.h		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
