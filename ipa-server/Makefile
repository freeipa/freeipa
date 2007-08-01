SUBDIRS=ipa-install xmlrpc-server
PYTHONDIR=$(DESTDIR)/usr/share/ipa/ipaserver

all:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install-ipaserver:
	-mkdir -p $(PYTHONDIR)
	install -m 644 ipaserver/*.py $(PYTHONDIR)

install: install-ipaserver
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -f *~
	rm -f ipaserver/*~
