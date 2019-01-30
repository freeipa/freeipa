NULL =

appdir = $(libexecdir)/ipa/custodia/
nodist_app_SCRIPTS =					\
	ipa-custodia-dmldap					\
	ipa-custodia-pki-tomcat				\
	ipa-custodia-pki-tomcat-wrapped		\
	ipa-custodia-ra-agent				\
	$(NULL)

dist_noinst_DATA = 						\
	ipa-custodia-dmldap.in				\
	ipa-custodia-pki-tomcat.in			\
	ipa-custodia-pki-tomcat-wrapped.in	\
	ipa-custodia-ra-agent.in			\
	$(NULL)

PYTHON_SHEBANG = $(nodist_app_SCRIPTS)

CLEANFILES = $(PYTHON_SHEBANG)

include $(top_srcdir)/Makefile.pythonscripts.am