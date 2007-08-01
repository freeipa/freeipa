PYTHONLIBDIR ?= $(shell  python -c "from distutils.sysconfig import *; print get_python_lib(1)")
PACKAGEDIR ?= $(DESTDIR)/$(PYTHONLIBDIR)/ipa

all: ;

install:
	-mkdir -p $(PACKAGEDIR)
	install -m 644 *.py $(PACKAGEDIR)

clean:
	rm -f *~ *.pyc