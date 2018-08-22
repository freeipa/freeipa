NULL =

oddjobdir = $(libexecdir)/ipa/oddjob
oddjobconfdir = $(sysconfdir)/oddjobd.conf.d
dbusconfdir = $(sysconfdir)/dbus-1/system.d

dist_noinst_DATA =		\
	com.redhat.idm.trust-fetch-domains.in	\
	$(NULL)

dist_oddjob_SCRIPTS =				\
	org.freeipa.server.conncheck		\
	$(NULL)

nodist_oddjob_SCRIPTS =				\
	com.redhat.idm.trust-fetch-domains	\
	$(NULL)


dist_dbusconf_DATA =					\
	etc/dbus-1/system.d/oddjob-ipa-trust.conf	\
	etc/dbus-1/system.d/org.freeipa.server.conf	\
	$(NULL)

dist_oddjobconf_DATA =					\
	etc/oddjobd.conf.d/oddjobd-ipa-trust.conf	\
	etc/oddjobd.conf.d/ipa-server.conf		\
	$(NULL)

PYTHON_SHEBANG = $(nodist_oddjob_SCRIPTS)
CLEANFILES = $(PYTHON_SHEBANG)

include $(top_srcdir)/Makefile.pythonscripts.am
