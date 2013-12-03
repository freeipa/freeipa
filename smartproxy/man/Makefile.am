# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL =

man1_MANS = 				\
		ipa-smartproxy.1

man5_MANS =				\
		ipa-smartproxy.conf.5

install-data-hook:
	@for i in $(man1_MANS) ; do gzip -f $(DESTDIR)$(man1dir)/$$i ; done
	@for i in $(man5_MANS) ; do gzip -f $(DESTDIR)$(man5dir)/$$i ; done

MAINTAINERCLEANFILES =          \
	Makefile.in		\
	$(NULL)
