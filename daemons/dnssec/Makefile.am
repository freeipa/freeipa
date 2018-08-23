# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

appdir = $(libexecdir)/ipa/
nodist_app_SCRIPTS = 		\
	ipa-dnskeysyncd		\
	ipa-dnskeysync-replica	\
	ipa-ods-exporter

dist_noinst_DATA = 				\
	ipa-dnskeysyncd.service.in		\
	ipa-ods-exporter.service.in		\
	ipa-ods-exporter.socket.in		\
	ipa-dnskeysyncd.in		\
	ipa-dnskeysync-replica.in	\
	ipa-ods-exporter.in


systemdsystemunit_DATA = 		\
	ipa-dnskeysyncd.service		\
	ipa-ods-exporter.service	\
	ipa-ods-exporter.socket

CLEANFILES = $(systemdsystemunit_DATA) $(nodist_app_SCRIPTS)

%: %.in Makefile
	sed \
		-e 's|@libexecdir[@]|$(libexecdir)|g' \
		-e 's|@localstatedir[@]|$(localstatedir)|g' \
		-e 's|@sysconfenvdir[@]|$(sysconfenvdir)|g' \
		-e 's|@ODS_USER[@]|$(ODS_USER)|g' \
		-e 's|@NAMED_GROUP[@]|$(NAMED_GROUP)|g' \
		'$(srcdir)/$@.in' >$@

dnssecconfdir = $(IPA_SYSCONF_DIR)/dnssec
install-data-hook:
	$(INSTALL) -d -m 755 $(DESTDIR)$(dnssecconfdir)

PYTHON_SHEBANG = 					\
	$(nodist_app_SCRIPTS)	\
	$(NULL)

include $(top_srcdir)/Makefile.pythonscripts.am
