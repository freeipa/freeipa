PYTHON ?= /usr/bin/python2
PYTHONLIBDIR ?= $(shell $(PYTHON) -c "from distutils.sysconfig import *; print(get_python_lib())")

all:
	# Pure Python; no need to build
	true

check:

.PHONY: install
install:
	if [ "$(DESTDIR)" = "" ]; then \
		$(PYTHON) setup.py install; \
	else \
		$(PYTHON) setup.py install --root $(DESTDIR); \
	fi

clean:
	rm -rf *~ *.pyc __pycache__/

distclean: clean

maintainer-clean: distclean
	rm -rf build
