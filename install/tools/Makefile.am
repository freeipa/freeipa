NULL =

SUBDIRS = 			\
        man			\
        $(NULL)

dist_noinst_DATA =		\
	ipa-ca-install.in		\
	ipa-dns-install.in		\
	ipa-kra-install.in		\
	ipa-server-install.in	\
	ipa-adtrust-install.in	\
	ipa-replica-conncheck.in	\
	ipa-replica-install.in	\
	ipa-replica-manage.in	\
	ipa-csreplica-manage.in	\
	ipa-server-certinstall.in  \
	ipa-server-upgrade.in	\
	ipactl.in			\
	ipa-compat-manage.in	\
	ipa-nis-manage.in		\
	ipa-managed-entries.in     \
	ipa-ldap-updater.in	\
	ipa-otptoken-import.in	\
	ipa-backup.in		\
	ipa-restore.in		\
	ipa-advise.in		\
	ipa-cacert-manage.in	\
	ipa-winsync-migrate.in	\
	ipa-pkinit-manage.in	\
	ipa-crlgen-manage.in	\
	ipa-custodia.in		\
	ipa-custodia-check.in	\
	ipa-httpd-kdcproxy.in	\
	ipa-pki-retrieve-key.in	\
	$(NULL)

nodist_sbin_SCRIPTS =		\
	ipa-ca-install		\
	ipa-dns-install		\
	ipa-kra-install		\
	ipa-server-install	\
	ipa-adtrust-install	\
	ipa-replica-conncheck	\
	ipa-replica-install	\
	ipa-replica-manage	\
	ipa-csreplica-manage	\
	ipa-server-certinstall  \
	ipa-server-upgrade	\
	ipactl			\
	ipa-compat-manage	\
	ipa-nis-manage		\
	ipa-managed-entries     \
	ipa-ldap-updater	\
	ipa-otptoken-import	\
	ipa-backup		\
	ipa-restore		\
	ipa-advise		\
	ipa-cacert-manage	\
	ipa-winsync-migrate	\
	ipa-pkinit-manage	\
	ipa-crlgen-manage	\
	$(NULL)

appdir = $(libexecdir)/ipa/
nodist_app_SCRIPTS =		\
	ipa-custodia		\
	ipa-custodia-check	\
	ipa-httpd-kdcproxy	\
	ipa-pki-retrieve-key	\
	$(NULL)

dist_app_SCRIPTS =		\
	ipa-httpd-pwdreader	\
	$(NULL)

PYTHON_SHEBANG = 					\
	$(nodist_sbin_SCRIPTS)	\
	$(nodist_app_SCRIPTS)	\
	$(NULL)

CLEANFILES = $(PYTHON_SHEBANG)

include $(top_srcdir)/Makefile.pythonscripts.am
