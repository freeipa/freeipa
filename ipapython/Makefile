PYTHON ?= /usr/bin/python2
PYTHONLIBDIR ?= $(shell $(PYTHON) -c "from distutils.sysconfig import *; print(get_python_lib())")

SUBDIRS = ipap11helper

all:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

check:

.PHONY: install
install:
	if [ "$(DESTDIR)" = "" ]; then \
		$(PYTHON) setup.py install; \
	else \
		$(PYTHON) setup.py install --root $(DESTDIR); \
	fi
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

clean:
	rm -f *~ *.pyc __pycache__/
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

distclean: clean
	rm -f setup.py ipa-python.spec version.py
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

maintainer-clean: distclean
	rm -rf build
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
