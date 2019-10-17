# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

NULL =

SUBDIRS =			\
        certmonger		\
        custodia		\
        html			\
        migration		\
        share			\
        ui			\
        tools			\
        updates			\
        restart_scripts		\
        wsgi			\
        oddjob			\
	gc                      \
	$(NULL)

install-exec-local:
	$(INSTALL) -d -m 700 $(DESTDIR)$(IPA_SYSCONF_DIR)/custodia
	$(INSTALL) -d -m 700 $(DESTDIR)$(localstatedir)/lib/ipa/backup
	$(INSTALL) -d -m 700 $(DESTDIR)$(localstatedir)/lib/ipa/gssproxy
	$(INSTALL) -d -m 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	$(INSTALL) -d -m 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/lib/ipa/pki-ca
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/lib/ipa/certs
	$(INSTALL) -d -m 700 $(DESTDIR)$(localstatedir)/lib/ipa/private
	$(INSTALL) -d -m 700 $(DESTDIR)$(localstatedir)/lib/ipa/passwds

uninstall-local:
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/certs
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/private
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/passwds
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa

EXTRA_DIST = README.schema
