SBINDIR=$(DESTDIR)/usr/sbin

all: ;

install:
	install -m 755 ipa-server-install $(SBINDIR)
	install -m 755 ipa-server-setupssl $(SBINDIR)
	$(MAKE) -C share $@

clean:
	$(MAKE) -C share $@
	rm -f *~ *.pyc