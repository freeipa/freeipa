PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib()")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa
CONFIGDIR ?= $(DESTDIR)/etc/ipa
TESTS = $(wildcard test/*.py)

all: ;

install:
	-mkdir -p $(PACKAGEDIR)
	install -m 644 *.py $(PACKAGEDIR)
	-mkdir -p $(CONFIGDIR)
	if ! [ -e $(CONFIGDIR)/ipa.conf ]; then \
		install -m 644 ipa.conf $(CONFIGDIR); \
	fi

clean:
	rm -f *~ *.pyc

.PHONY: test
test: $(subst .py,.tst,$(TESTS))

%.tst: %.py
	python $<


