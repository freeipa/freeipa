NULL =

appdir = $(libexecdir)/certmonger/
nodist_app_SCRIPTS =					\
	dogtag-ipa-ca-renew-agent-submit	\
	ipa-server-guard			\
	$(NULL)

# ipathinca renewal helper scripts (shell scripts, installed as-is)
# Note: stop_pkicad not needed - ipathinca uses graceful reload via SIGHUP
dist_app_SCRIPTS =				\
	renew_ca_cert				\
	$(NULL)

dist_noinst_DATA = 				\
	dogtag-ipa-ca-renew-agent-submit.in	\
	ipa-server-guard.in			\
	$(NULL)

PYTHON_SHEBANG = $(nodist_app_SCRIPTS)

CLEANFILES = $(PYTHON_SHEBANG)

include $(top_srcdir)/Makefile.pythonscripts.am
