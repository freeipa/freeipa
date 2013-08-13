# This file will be processed with automake-1.7 to create Makefile.in

AUTOMAKE_OPTIONS = 1.7

NULL=

man1_MANS =             \
	ipa-run-tests.1     \
	ipa-test-config.1   \
	ipa-test-task.1     \
		$(NULL)

install-data-hook:
	@for i in $(man1_MANS) ; do gzip -f $(DESTDIR)$(man1dir)/$$i ; done

MAINTAINERCLEANFILES =      \
	Makefile.in             \
	$(NULL)
