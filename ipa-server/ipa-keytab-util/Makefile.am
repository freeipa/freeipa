NULL =

sbin_PROGRAMS =			\
	ipa-keytab-util		\
	$(NULL)

ipa_keytab_util_SOURCES =	\
	ipa-keytab-util.c	\
	$(NULL)

ipa_keytab_util_LDADD = 	\
	-lcap			\
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in

install-exec-hook:
	-chown root:apache $(DESTDIR)$(sbindir)/ipa-keytab-util
	-chmod o-rwxs $(DESTDIR)$(sbindir)/ipa-keytab-util
	-chmod ug+s $(DESTDIR)$(sbindir)/ipa-keytab-util
