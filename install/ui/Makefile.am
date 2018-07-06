AUTOMAKE_OPTIONS = 1.7

NULL =

SUBDIRS =  				\
	build				\
	css				\
	images				\
	src				\
	$(NULL)

appdir = $(IPA_DATA_DIR)/ui
app_DATA =				\
	favicon.ico			\
	index.html 			\
	ie.css				\
	ipa.css				\
	reset_password.html		\
	sync_otp.html		\
	$(NULL)

EXTRA_DIST =                            \
        doc                             \
        jsl.conf                        \
        less                            \
        README-LICENSE.txt              \
        test                            \
        util                            \
        $(app_DATA)                     \
        $(NULL)

install-data-hook:
	$(INSTALL) -d -m 755 $(DESTDIR)$(appdir)/js/plugins

clean-local:
	rm -rf package-lock.json node_modules
