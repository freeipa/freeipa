PYTHONLIBDIR ?= $(shell  python2 -c "from distutils.sysconfig import *; print get_python_lib()")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
CONFIGDIR ?= $(DESTDIR)/etc/ipa

all:
	python2 setup.py build

install:
	if [ "$(DESTDIR)" = "" ]; then \
		python2 setup.py install; \
	else \
		python2 setup.py install --root $(DESTDIR); \
	fi

clean:
	rm -rf build

distclean: clean

maintainer-clean: distclean
