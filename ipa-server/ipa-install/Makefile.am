NULL =

SUBDIRS =			\
	share			\
	$(NULL)

sbin_SCRIPTS =			\
	ipa-server-install	\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_SCRIPTS =			\
	ipa-server-setupssl	\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_SCRIPTS)		\
	$(sbin_SCRIPTS)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
