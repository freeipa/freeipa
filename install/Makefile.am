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
        wsgi			\
        oddjob			\
	$(NULL)

install-exec-local:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	chmod 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	chmod 700 $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	mkdir -p $(DESTDIR)$(localstatedir)/lib/ipa/pki-ca
	chmod 755 $(DESTDIR)$(localstatedir)/lib/ipa/pki-ca

uninstall-local:
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysrestore
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa/sysupgrade
	-rmdir $(DESTDIR)$(localstatedir)/lib/ipa

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
