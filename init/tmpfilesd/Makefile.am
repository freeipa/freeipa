dist_noinst_DATA =     \
	ipa.conf.in

systemdtmpfiles_DATA =         \
	ipa.conf

CLEANFILES = $(systemdtmpfiles_DATA)

%: %.in Makefile
	cp '$(srcdir)/$@.in' $@
