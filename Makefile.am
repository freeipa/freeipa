SUBDIRS = asn1 util client contrib daemons init install ipaclient ipalib ipaplatform ipapython ipaserver ipatests po

MOSTLYCLEANFILES = ipasetup.pyc ipasetup.pyo

# user-facing scripts
dist_bin_SCRIPTS = ipa

# files required for build but not installed
dist_noinst_SCRIPTS = ignore_import_errors.py \
		      lite-server.py \
		      makeapi \
		      makeaci \
		      make-doc \
		      make-test \
		      pylint_plugins.py

EXTRA_DIST = .mailmap \
	     ACI.txt \
	     API.txt \
	     BUILD.txt \
	     Contributors.txt \
	     COPYING.openssl \
	     contrib \
	     doc \
	     pylintrc \
	     pytest.ini

# convenience targets for RPM build
RPMBUILD ?= $(abs_builddir)/rpmbuild
TARBALL = $(PACKAGE)-$(VERSION).tar.gz
rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p $(top_builddir)/dist/rpms
	mkdir -p $(top_builddir)/dist/srpms

rpms: dist-gzip rpmroot rpmdistdir
	cp $(top_builddir)/$(TARBALL) $(RPMBUILD)/SOURCES/
	rpmbuild --define "_topdir $(RPMBUILD)" -ba $(top_builddir)/$(PACKAGE).spec
	cp $(RPMBUILD)/RPMS/*/*.rpm $(top_builddir)/dist/rpms/
	cp $(RPMBUILD)/SRPMS/*.src.rpm $(top_builddir)/dist/srpms/

.PHONY: lint
if WITH_PYLINT
PYLINT_TARGET = pylint
endif WITH_PYLINT
lint: $(PYLINT_TARGET)

.PHONY: pylint
pylint:
	FILES=`find $(top_srcdir) \
		-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
		-path '*/.*' -o \
		-path '*.in' -o \
		-path './dist/*' -o \
		-path './lextab.py' -o \
		-path './yacctab.py' -o \
		-name '*~' -o \
		-name \*.py -print -o \
		-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print`; \
	echo "Pylint is running, please wait ..."; \
	PYTHONPATH=$(top_srcdir) $(PYLINT) \
		--rcfile=$(top_srcdir)/pylintrc $${FILES}
