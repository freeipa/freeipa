# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

NULL =

SUBDIRS =			\
        certmonger		\
        conf			\
        ffextension		\
        html			\
        migration		\
        share			\
        ui			\
        tools			\
        updates			\
        po			\
        restart_scripts		\
	$(NULL)

install-exec-local:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	chmod 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	chmod 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	mkdir -p $(DESTDIR)$(localstatedir)/cache/ipa/sessions
	chmod 700 $(DESTDIR)$(localstatedir)/cache/ipa/sessions
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/pki-ca/publish
	chmod 755 $(DESTDIR)$(localstatedir)/lib/ipa/pki-ca
	chmod 755 $(DESTDIR)$(localstatedir)/lib/ipa/pki-ca/publish

uninstall-local:
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa
	-rmdir $(DESTDIR)$(localstatedir)/cache/ipa/sessions
	-rmdir $(DESTDIR)$(localstatedir)/cache/ipa

DISTCLEANFILES =		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	intltool-*.in		\
	compile			\
	configure		\
	COPYING			\
	INSTALL			\
	install-sh		\
	missing			\
	mkinstalldirs		\
	config.guess		\
	ltmain.sh		\
	config.sub		\
	depcomp			\
	Makefile.in		\
	config.h.*		\
	aclocal.m4		\
	version.m4		\
	ipa-client.spec		\
	py-compile		\
	$(NULL)
