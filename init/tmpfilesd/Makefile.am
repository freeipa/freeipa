dist_noinst_DATA =     \
	ipa.conf.in    \
	ipa-dnssec.conf.in

systemdtmpfiles_DATA =         \
	ipa.conf

appdir = $(IPA_DATA_DIR)
dist_app_DATA =	\
	ipa-dnssec.conf

CLEANFILES = $(systemdtmpfiles_DATA) $(app_DATA)

%: %.in Makefile
	sed \
		-e 's|@HTTPD_GROUP[@]|$(HTTPD_GROUP)|g;s|@ODS_USER[@]|$(ODS_USER)|g;s|@NAMED_GROUP[@]|$(NAMED_GROUP)|g' \
		 '$(srcdir)/$@.in' >$@
