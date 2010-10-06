PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib()")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
CONFIGDIR ?= $(DESTDIR)/etc/ipa

all:
	python setup.py build

install:
	if [ "$(DESTDIR)" = "" ]; then \
		python setup.py install; \
	else \
		python setup.py install --root $(DESTDIR); \
	fi

clean:
	rm -rf build

distclean: clean

maintainer-clean: distclean
