PYTHONLIBDIR ?= /usr/share/ipa/python
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipainstall
SBINDIR = $(DESTDIR)/usr/sbin

all: ;

install:
	-mkdir -p $(PACKAGEDIR)
	install -m 644 ipainstall/*.py $(PACKAGEDIR)
	install -m 755 ipa-server-install $(SBINDIR)
	install -m 755 ipa-server-setupssl $(SBINDIR)

clean:
	rm -f *~ *.pyc