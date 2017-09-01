NULL =

appdir = $(IPA_SYSCONF_DIR)/html
app_DATA =                              \
	ssbrowser.html			\
	unauthorized.html       	\
	$(NULL)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

# Default user-modifiable HTML files are installed into /etc.
# /usr points to these modifiable files in /etc
# This is ugly but we do not have time to change it right now.
# Relative paths must be used to ensure that symlinks created in buildroot
# work after installation.
htmldatadir = $(datarootdir)/ipa/html
install-data-hook:
	$(INSTALL) -d -m 755 $(DESTDIR)$(htmldatadir)
	for FILE in $(app_DATA); do				\
		$(LN_S) --force --relative			\
			$(DESTDIR)$(appdir)/$${FILE}		\
			$(DESTDIR)$(htmldatadir)/$${FILE};	\
	done
