PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib()")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
CONFIGDIR ?= $(DESTDIR)/etc/ipa
TESTS = $(wildcard test/*.py)

SUBDIRS = py_default_encoding

all:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install:
	if [ "$(DESTDIR)" = "" ]; then \
		python setup.py install; \
	else \
		python setup.py install --root $(DESTDIR); \
	fi
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

clean:
	rm -f *~ *.pyc
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

.PHONY: test
test: $(subst .py,.tst,$(TESTS))

%.tst: %.py
	python $<
