PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib()")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
CONFIGDIR ?= $(DESTDIR)/etc/ipa
TESTS = $(wildcard test/*.py)

all: ;

install:
	if [ "$(DESTDIR)" = "" ]; then \
		python setup.py install; \
	else \
		python setup.py install --root $(DESTDIR); \
	fi

clean:
	rm -f *~ *.pyc

distclean: clean

.PHONY: test
test: $(subst .py,.tst,$(TESTS))

%.tst: %.py
	python $<
