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
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in

initdir=$(sysconfdir)/rc.d/init.d

install-data-hook: ipa_webgui.init
	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 755 $(DESTDIR)$(initdir); \
	fi

	$(INSTALL_SCRIPT) $(srcdir)/ipa_webgui.init $(DESTDIR)$(initdir)/ipa_webgui

uninstall-hook:
	rm -f $(DESTDIR)$(initdir)/ipa_webgui
