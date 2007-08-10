SBINDIR=$(DESTDIR)/usr/sbin

all: ;

install:
	-mkdir $(SBINDIR)
	install -m 755 ipa-server-install $(SBINDIR)
	install -m 755 ipa-server-setupssl $(SBINDIR)
	$(MAKE) -C share $@
	$(MAKE) -C test $@

clean:
	$(MAKE) -C share $@
	rm -f *~ *.pyc
