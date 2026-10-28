dist_noinst_DATA =     \
	ipa.conf.in

systemdsysusers_DATA =         \
	ipa.conf

CLEANFILES = $(systemdsysusers_DATA)

%: %.in Makefile
	sed \
		-e 's|@HTTPD_USER[@]|$(HTTPD_USER)|g' \
		'$(srcdir)/$@.in' >$@
