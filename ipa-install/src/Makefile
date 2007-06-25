PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib(1)")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
SBINDIR = $(DESTDIR)/usr/sbin

all: ;

install:
	-mkdir -p $(PACKAGEDIR)
	install -m 644 ipa/*.py $(PACKAGEDIR)
	install -m 755 ipa-server-install $(SBINDIR)
	install -m 755 ipa-server-setupssl $(SBINDIR)

clean:
	rm -f *~ *.pyc