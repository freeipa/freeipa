SUBDIRS=man
SBINDIR = $(DESTDIR)/usr/sbin


all: ;
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install:
	install -m 755 ipa-adduser $(SBINDIR)
	install -m 755 ipa-finduser $(SBINDIR)
	install -m 755 ipa-usermod $(SBINDIR)
	install -m 755 ipa-deluser $(SBINDIR)
	install -m 755 ipa-addgroup $(SBINDIR)
	install -m 755 ipa-delgroup $(SBINDIR)
	install -m 755 ipa-findgroup $(SBINDIR)
	install -m 755 ipa-groupmod $(SBINDIR)
	install -m 755 ipa-passwd $(SBINDIR)
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install-man:
	install -m 644

clean:
	rm -f *~ *.pyc

distclean: clean

test:
