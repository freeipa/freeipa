# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL=

man1_MANS = 				\
	ipa-replica-install.1		\
	ipa-replica-manage.1		\
	ipa-replica-prepare.1		\
	ipa-server-certinstall.1	\
	ipa-server-install.1		\
	ipa-ldap-updater.1

man8_MANS =				\
	ipactl.8			\
	ipa_kpasswd.8			\
	ipa_webgui.8

install-data-hook:
	@for i in $(man1_MANS) ; do gzip -f $(DESTDIR)$(man1dir)/$$i ; done
	@for i in $(man8_MANS) ; do gzip -f $(DESTDIR)$(man8dir)/$$i ; done

MAINTAINERCLEANFILES =          \
        Makefile.in             \
        $(NULL)
