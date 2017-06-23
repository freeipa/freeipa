# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

dist_noinst_DATA = 			\
	ipa-named-pkcs11.service.in \
	ipa-custodia.service.in		\
	ipa.service.in

systemdsystemunit_DATA = 	\
	ipa-named-pkcs11.service \
	ipa-custodia.service	\
	ipa.service

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
