NULL =

appdir = $(libexecdir)/certmonger/
nodist_app_SCRIPTS =					\
	dogtag-ipa-ca-renew-agent-submit	\
	ipa-server-guard			\
	$(NULL)

dist_noinst_DATA = 				\
	dogtag-ipa-ca-renew-agent-submit.in	\
	ipa-server-guard.in			\
	$(NULL)

PYTHON_SHEBANG = $(nodist_app_SCRIPTS)

CLEANFILES = $(PYTHON_SHEBANG)

include $(top_srcdir)/Makefile.pythonscripts.am