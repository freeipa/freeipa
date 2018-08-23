NULL =

appdir = $(libexecdir)/ipa/certmonger
app_DATA =                              \
	restart_dirsrv			\
	restart_httpd			\
	renew_ca_cert			\
	renew_kdc_cert			\
	renew_ra_cert			\
	stop_pkicad			\
	renew_ra_cert_pre		\
	$(NULL)

EXTRA_DIST =                            \
	restart_dirsrv.in			\
	restart_httpd.in			\
	renew_ca_cert.in			\
	renew_kdc_cert.in			\
	renew_ra_cert.in			\
	stop_pkicad.in			\
	renew_ra_cert_pre.in		\
	$(NULL)

PYTHON_SHEBANG = $(app_DATA)
CLEANFILES = $(PYTHON_SHEBANG)

include $(top_srcdir)/Makefile.pythonscripts.am
