SUBDIRS=ipa-install
PYTHONDIR=$(DESTDIR)/usr/share/ipa/ipaclient

all:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install-ipaclient:
	-mkdir -p $(PYTHONDIR)
	install -m 644 ipaclient/*.py $(PYTHONDIR)

install: install-ipaclient
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -f *~
	rm -f ipaclient/*~
