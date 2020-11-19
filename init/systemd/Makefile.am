# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

NULL =

dist_noinst_DATA = 			\
	ipa-custodia.service.in		\
	ipa.service.in			\
	ipa-ccache-sweep.service.in	\
	ipa-ccache-sweep.timer.in	\
	$(NULL)

systemdsystemunit_DATA = 	\
	ipa-custodia.service	\
	ipa.service				\
	ipa-ccache-sweep.service	\
	ipa-ccache-sweep.timer	\
	$(NULL)

CLEANFILES = $(systemdsystemunit_DATA)

%: %.in Makefile
	sed \
		-e 's|@bindir[@]|$(bindir)|g' \
		-e 's|@IPA_SYSCONF_DIR[@]|$(IPA_SYSCONF_DIR)|g' \
		-e 's|@localstatedir[@]|$(localstatedir)|g' \
		-e 's|@sbindir[@]|$(sbindir)|g' \
		-e 's|@libexecdir[@]|$(libexecdir)|g' \
		-e 's|@sysconfenvdir[@]|$(sysconfenvdir)|g' \
		'$(srcdir)/$@.in' >$@
