SUBDIRS=man
SBINDIR = $(DESTDIR)/usr/sbin


all: ;
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install:
	install -m 755 ipa-adduser $(SBINDIR)
	install -m 755 ipa-finduser $(SBINDIR)
	install -m 755 ipa-moduser $(SBINDIR)
	install -m 755 ipa-deluser $(SBINDIR)
	install -m 755 ipa-lockuser $(SBINDIR)
	install -m 755 ipa-addgroup $(SBINDIR)
	install -m 755 ipa-delgroup $(SBINDIR)
	install -m 755 ipa-findgroup $(SBINDIR)
	install -m 755 ipa-modgroup $(SBINDIR)
	install -m 755 ipa-passwd $(SBINDIR)
	install -m 755 ipa-pwpolicy $(SBINDIR)
	install -m 755 ipa-addservice $(SBINDIR)
	install -m 755 ipa-delservice $(SBINDIR)
	install -m 755 ipa-findservice $(SBINDIR)
	install -m 755 ipa-adddelegation $(SBINDIR)
	install -m 755 ipa-deldelegation $(SBINDIR)
	install -m 755 ipa-listdelegation $(SBINDIR)
	install -m 755 ipa-moddelegation $(SBINDIR)
	install -m 755 ipa-defaultoptions $(SBINDIR)
	install -m 755 ipa-change-master-key $(SBINDIR)

	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install-man:
	install -m 644

clean:
	rm -f *~ *.pyc

distclean: clean
	rm -f ipa-admintools.spec

maintainer-clean: distclean

test:
