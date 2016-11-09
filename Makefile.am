SUBDIRS = asn1 util client contrib daemons init install ipaclient ipalib ipaplatform ipapython ipaserver ipatests po

MOSTLYCLEANFILES = ipasetup.pyc ipasetup.pyo \
		   ignore_import_errors.pyc ignore_import_errors.pyo \
		   ipasetup.pyc ipasetup.pyo \
		   lite-server.pyc lite-server.pyo \
		   pylint_plugins.pyc pylint_plugins.pyo \
		   $(TARBALL)

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

clean-local:
	rm -rf "$(RPMBUILD)"
	rm -rf "$(top_builddir)/dist"
	rm -rf "$(top_srcdir)/__pycache__"

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
if WITH_POLINT
POLINT_TARGET = polint
endif WITH_POLINT
if WITH_PYLINT
PYLINT_TARGET = pylint
endif WITH_PYLINT
if WITH_JSLINT
JSLINT_TARGET = jslint
endif WITH_JSLINT
lint: acilint apilint $(POLINT_TARGET) $(PYLINT_TARGET) $(JSLINT_TARGET)

.PHONY: acilint
acilint:
	cd $(srcdir); ./makeaci --validate

.PHONY: apilint
apilint:
	cd $(srcdir); ./makeapi --validate

.PHONY: polint
polint:
	$(MAKE) -C $(srcdir)/po validate-src-strings

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

.PHONY: jslint jslint-ui jslint-ui-test jslint-html
jslint: jslint-ui jslint-ui-test jslint-html

# create temporary symlinks to allow jslint to find libs/loader.js
jslint-ui:
	cd $(top_srcdir)/install/ui;				\
	$(MKDIR_P) js;						\
	rm -f js/libs;						\
	$(LN_S) ../src/libs js/libs;				\
	jsl -nologo -nosummary -nofilelisting -conf jsl.conf;	\
	rm js/libs;						\
	rmdir js

jslint-ui-test:
	cd $(top_srcdir)/install/ui/test;			\
	jsl -nologo -nosummary -nofilelisting -conf jsl.conf

jslint-html:
	cd $(top_srcdir)/install/html; 				\
	jsl -nologo -nosummary -nofilelisting -conf jsl.conf
