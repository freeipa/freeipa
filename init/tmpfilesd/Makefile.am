dist_noinst_DATA =     \
	ipa.conf.in

systemdtmpfiles_DATA =         \
	ipa.conf

CLEANFILES = $(systemdtmpfiles_DATA)

%: %.in Makefile
	sed -e 's|@localstatedir[@]|$(localstatedir)|g' '$(srcdir)/$@.in' >$@
