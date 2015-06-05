NULL =

oddjobdir = $(libexecdir)/ipa
oddjobconfdir = $(sysconfdir)/oddjobd.conf.d
dbusconfdir = $(sysconfdir)/dbus-1/system.d

oddjob_SCRIPTS =				\
	com.redhat.idm.trust-fetch-domains	\
	$(NULL)

dbusconf_DATA =						\
	etc/dbus-1/system.d/oddjob-ipa-trust.conf	\
	$(NULL)

oddjobconf_DATA =					\
	etc/oddjobd.conf.d/oddjobd-ipa-trust.conf	\
	$(NULL)


#EXTRA_DIST =				\
#	$(oddjob_SCRIPTS)		\
#	$(dbusconf_DATA)		\
#	$(oddjobconf_DATA)		\
#	$(NULL)

MAINTAINERCLEANFILES =			\
	*~				\
	Makefile.in
