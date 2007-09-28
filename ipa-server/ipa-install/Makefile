SHAREDIR=$(DESTDIR)/usr/share/ipa
SBINDIR=$(DESTDIR)/usr/sbin

all: ;

install:
	-mkdir $(SBINDIR)
	install -m 755 ipa-server-install $(SBINDIR)
	install -m 755 ipa-server-setupssl $(SHAREDIR)
	$(MAKE) -C share $@
	$(MAKE) -C test $@

clean:
	$(MAKE) -C share $@
	rm -f *~ *.pyc
