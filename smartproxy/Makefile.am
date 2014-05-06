# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL =

etcdir = $(IPA_SYSCONF_DIR)
etc_DATA =			\
	ipa-smartproxy.conf	\
	$(NULL)

appdir = $(IPA_DATA_DIR)/smartproxy
app_DATA =			\
	ipa-smartproxy.py	\
	$(NULL)

SUBDIRS =			\
	man			\
	$(NULL)

EXTRA_DIST =			\
	$(app_DATA)		\
	$(etc_DATA)		\
	$(rotate_DATA)		\
	$(NULL)

DISTCLEANFILES =		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	aclocal.m4		\
	configure		\
	install-sh		\
	missing			\
	Makefile.in		\
	$(NULL)
