# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL =

man_MANS = 				\
		ipa-getkeytab.1		\
		ipa-rmkeytab.1		\
		ipa-client-install.1	\
		ipa-join.1
	
install-data-hook:
	@for i in $(man_MANS) ; do gzip -f $(DESTDIR)$(man1dir)/$$i ; done

MAINTAINERCLEANFILES =          \
	Makefile.in		\
	$(NULL)
