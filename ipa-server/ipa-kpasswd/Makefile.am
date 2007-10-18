NULL =

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(LDAP_CFLAGS)						\
	$(KRB5_CFLAGS)						\
	$(WARN_CFLAGS)						\
	$(NULL)

sbin_PROGRAMS =			\
	ipa_kpasswd		\
	$(NULL)

ipa_kpasswd_SOURCES = 		\
	ipa_kpasswd.c		\
	$(NULL)

ipa_kpasswd_LDADD =		\
	$(LDAP_LIBS)		\
	$(KRB5_LIBS)		\
	$(NULL)

EXTRA_DIST =			\
	README			\
	ipa-kpasswd.init	\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in

initdir=$(sysconfdir)/rc.d/init.d

install-data-hook: ipa-kpasswd.init

	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 755 $(DESTDIR)$(initdir); \
	fi

	$(INSTALL_SCRIPT) $(srcdir)/ipa-kpasswd.init $(DESTDIR)$(initdir)/ipa-kpasswd

uninstall-hook:
	rm -f $(DESTDIR)$(initdir)/ipa-kpasswd
