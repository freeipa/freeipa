PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib(1)")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
CONFIGDIR ?= $(DESTDIR)/etc/ipa

all: ;

install:
	-mkdir -p $(PACKAGEDIR)
	install -m 644 *.py $(PACKAGEDIR)
	-mkdir -p $(CONFIGDIR)
	install -m 644 ipa.conf $(CONFIGDIR)

clean:
	rm -f *~ *.pyc