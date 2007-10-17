NULL =

SUBDIRS =			\
	ipagui			\
	ipa_gui.egg-info	\
	$(NULL)

sbin_SCRIPTS =			\
	ipa-webgui		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa-webgui.cfg		\
	$(NULL)

EXTRA_DIST =			\
	README.txt		\
	$(sbin_SCRIPTS)		\
	$(app_DATA)		\
	ipa-webgui.init		\
	dev.cfg			\
	sample-prod.cfg		\
	setup.py		\
	start-ipagui.py		\
	test.cfg		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in

initdir=$(sysconfdir)/rc.d/init.d

install-data-hook: ipa-webgui.init
	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 755 $(DESTDIR)$(initdir); \
	fi

	$(INSTALL_SCRIPT) $(srcdir)/ipa-webgui.init $(DESTDIR)$(initdir)/ipa-webgui

uninstall-hook:
	rm -f $(DESTDIR)$(initdir)/ipa-webgui
