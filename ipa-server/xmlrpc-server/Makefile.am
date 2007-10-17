NULL =

SUBDIRS =			\
	test			\
	$(NULL)

htmldir = $(IPA_DATA_DIR)/html
html_DATA =			\
	ssbrowser.html		\
	unauthorized.html	\
	$(NULL)

serverdir = $(IPA_DATA_DIR)/ipaserver
server_PYTHON =			\
	funcs.py		\
	ipaxmlrpc.py		\
	$(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA =			\
	ipa.conf		\
	$(NULL)

EXTRA_DIST =			\
	README			\
	$(app_DATA)		\
	$(html_DATA)		\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in
