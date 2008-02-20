NULL =

SUBDIRS =			\
	ipagui			\
	ipa_gui.egg-info	\
	$(NULL)

sbin_SCRIPTS =			\
	ipa_webgui		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa_webgui.cfg		\
	$(NULL)

LINGUAS = ja

mo = $(foreach lang,$(LINGUAS),locales/$(lang)/LC_MESSAGES/messages.mo)
po = $(foreach lang,$(LINGUAS),locales/$(lang)/LC_MESSAGES/messages.po)
$(mo): $(po)
	tg-admin i18n compile

noinst_DATA = $(mo)

EXTRA_DIST =			\
	README.txt		\
	$(sbin_SCRIPTS)		\
	$(app_DATA)		\
	ipa_webgui.init		\
	dev.cfg			\
	sample-prod.cfg		\
	setup.py		\
	start-ipagui.py		\
	test.cfg		\
	$(po)			\
	locales/messages.pot	\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in

CLEANFILES =			\
	$(mo)

initdir=$(sysconfdir)/rc.d/init.d

install-data-hook: ipa_webgui.init
	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 755 $(DESTDIR)$(initdir); \
	fi

	$(INSTALL_SCRIPT) $(srcdir)/ipa_webgui.init $(DESTDIR)$(initdir)/ipa_webgui

	for mo in $(mo); do \
		$(mkinstalldirs) $(DESTDIR)$(appdir)/`dirname $$mo`; \
		$(INSTALL_DATA) $$mo $(DESTDIR)$(appdir)/`dirname $$mo`; \
	done
 
uninstall-hook:
	rm -f $(DESTDIR)$(initdir)/ipa_webgui
	for mo in $(mo); do \
		rm -f $(DESTDIR)$(appdir)/$$mo; \
	done
