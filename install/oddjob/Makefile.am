NULL =

oddjobdir = $(libexecdir)/ipa/oddjob
oddjobconfdir = $(sysconfdir)/oddjobd.conf.d
dbusconfdir = $(sysconfdir)/dbus-1/system.d

oddjob_SCRIPTS =				\
	com.redhat.idm.trust-fetch-domains	\
	org.freeipa.server.conncheck		\
	$(NULL)

dbusconf_DATA =						\
	etc/dbus-1/system.d/oddjob-ipa-trust.conf	\
	etc/dbus-1/system.d/org.freeipa.server.conf	\
	$(NULL)

oddjobconf_DATA =					\
	etc/oddjobd.conf.d/oddjobd-ipa-trust.conf	\
	etc/oddjobd.conf.d/ipa-server.conf		\
	$(NULL)


#EXTRA_DIST =				\
#	$(oddjob_SCRIPTS)		\
#	$(dbusconf_DATA)		\
#	$(oddjobconf_DATA)		\
#	$(NULL)

MAINTAINERCLEANFILES =			\
	*~				\
	Makefile.in
