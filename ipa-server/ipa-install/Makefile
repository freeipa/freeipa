include ../Makefile.common

all: ;

install:
	-mkdir $(SBINDIR)
	install -m 755 ipa-server-install $(SBINDIR)
	install -m 755 ipa-server-setupssl $(SHAREDIR)

	-mkdir -p $(SHAREDIR)
	install -m 644 share/*.ldif $(SHAREDIR)
	install -m 644 share/*.template $(SHAREDIR)

	$(MAKE) -C test $@

clean:
	rm -f *~ *.pyc
	rm -f share/*~
