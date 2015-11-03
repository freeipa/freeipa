PYTHON ?= /usr/bin/python2
PYTHONLIBDIR ?= $(shell $(PYTHON) -c "from distutils.sysconfig import *; print(get_python_lib())")
PYTHONVERSION ?= $(shell $(PYTHON) -c "import sys; print(sys.version_info[0])")

all:
	if [ "$(PYTHONVERSION)" = "2" ]; then \
		python2 setup.py build; \
	fi

install:
	# Skip this module under Python 3
	if [ "$(PYTHONVERSION)" = "2" ]; then \
		if [ "$(DESTDIR)" = "" ]; then \
			python2 setup.py install; \
		else \
			python2 setup.py install --root $(DESTDIR); \
		fi; \
	fi

clean:
	rm -rf build

distclean: clean

maintainer-clean: distclean
