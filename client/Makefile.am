# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7 subdir-objects

NULL =

IPA_CONF_FILE=$(sysconfdir)/ipa/default.conf

AM_CPPFLAGS =							\
	-I$(srcdir)						\
	-I$(top_srcdir)/util					\
	-I$(top_srcdir)/asn1					\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	-DLOCALEDIR=\""$(localedir)"\"				\
	-DIPACONFFILE=\""$(IPA_CONF_FILE)"\"			\
	$(KRB5_CFLAGS)						\
	$(LDAP_CFLAGS)						\
	$(SASL_CFLAGS)						\
	$(POPT_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(INI_CFLAGS)						\
	$(NULL)

sbin_PROGRAMS =			\
	ipa-getkeytab		\
	ipa-rmkeytab		\
	ipa-join		\
	$(NULL)

sbin_SCRIPTS =			\
	ipa-certupdate		\
	ipa-client-automount	\
	ipa-client-install	\
	ipa-client-samba	\
	ipa-epn                 \
	$(NULL)

appdir = $(libexecdir)/ipa/acme
nodist_app_SCRIPTS =		\
	certbot-dns-ipa		\
	$(NULL)

ipa_getkeytab_SOURCES =		\
	ipa-getkeytab.c		\
	ipa-client-common.c	\
	$(KRB5_UTIL_SRCS)	\
	$(NULL)

ipa_getkeytab_LDADD = 		\
	$(top_builddir)/asn1/libipaasn1.la	\
	$(top_builddir)/util/libutil.la	\
	$(KRB5_LIBS)		\
	$(LDAP_LIBS)		\
	$(SASL_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(RESOLV_LIBS)		\
	$(INI_LIBS)		\
	$(NULL)

ipa_rmkeytab_SOURCES =		\
	ipa-rmkeytab.c		\
	ipa-client-common.c	\
	$(NULL)

ipa_rmkeytab_LDADD = 		\
	$(KRB5_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(NULL)

ipa_join_SOURCES =		\
	config.c		\
	ipa-client-common.c	\
	ipa-join.c		\
	$(NULL)

ipa_join_LDADD = 		\
	$(top_builddir)/util/libutil.la	\
	$(KRB5_LIBS)		\
	$(LDAP_LIBS)		\
	$(SASL_LIBS)		\
	$(XMLRPC_LIBS)		\
	$(JANSSON_LIBS)		\
	$(LIBCURL_LIBS)		\
	$(POPT_LIBS)		\
	$(LIBINTL_LIBS)         \
	$(NULL)

SUBDIRS =			\
	share		        \
	man			\
	sysconfig	        \
	systemd			\
	$(NULL)
#       init                    


noinst_HEADERS =		\
	ipa-client-common.h

EXTRA_DIST =			\
	ipa-certupdate.in	\
	ipa-client-automount.in	\
	ipa-client-install.in	\
	ipa-client-samba.in	\
	ipa-epn.in              \
	certbot-dns-ipa.in      \
	$(NULL)

install-data-hook:
	$(INSTALL) -d -m 755 $(DESTDIR)$(IPA_SYSCONF_DIR)/nssdb
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/lib/ipa-client/pki
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/lib/ipa-client/sysrestore


PYTHON_SHEBANG = \
	$(sbin_SCRIPTS) \
	$(nodist_app_SCRIPTS) \
	$(NULL)

include $(top_srcdir)/Makefile.pythonscripts.am
