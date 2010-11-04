NULL =

INCLUDES =							\
	-I.							\
	-I$(srcdir)						\
	-DPREFIX=\""$(prefix)"\" 				\
	-DBINDIR=\""$(bindir)"\"				\
	-DLIBDIR=\""$(libdir)"\" 				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DDATADIR=\""$(datadir)"\"				\
	$(AM_CFLAGS)						\
	$(OPENLDAP_CFLAGS)						\
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
	$(OPENLDAP_LIBS)		\
	$(KRB5_LIBS)		\
	$(NULL)

install-exec-local:
	mkdir -p $(DESTDIR)$(localstatedir)/cache/ipa/kpasswd
	chmod 700 $(DESTDIR)$(localstatedir)/cache/ipa/kpasswd

uninstall-local:
	-rmdir $(DESTDIR)$(localstatedir)/cache/ipa/kpasswd
	-rmdir $(DESTDIR)$(localstatedir)/cache/ipa

EXTRA_DIST =			\
	README			\
	ipa_kpasswd.init	\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in

initdir=$(sysconfdir)/rc.d/init.d

install-data-hook: ipa_kpasswd.init

	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 755 $(DESTDIR)$(initdir); \
	fi

	$(INSTALL_SCRIPT) $(srcdir)/ipa_kpasswd.init $(DESTDIR)$(initdir)/ipa_kpasswd

uninstall-hook:
	rm -f $(DESTDIR)$(initdir)/ipa_kpasswd
