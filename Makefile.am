ACLOCAL_AMFLAGS = -I m4

if ENABLE_SERVER
    SERVER_SUBDIRS = daemons init install ipaserver
endif

if WITH_IPATESTS
    IPATESTS_SUBDIRS = ipatests
endif

IPACLIENT_SUBDIRS = ipaclient ipalib ipapython
IPA_PLACEHOLDERS = freeipa ipa ipaplatform ipaserver ipatests
SUBDIRS = asn1 util client contrib po pypi \
	$(IPACLIENT_SUBDIRS) ipaplatform $(IPATESTS_SUBDIRS) $(SERVER_SUBDIRS)

MOSTLYCLEANFILES = ipasetup.pyc ipasetup.pyo \
		   ignore_import_errors.pyc ignore_import_errors.pyo \
		   ipasetup.pyc ipasetup.pyo \
		   pylint_plugins.pyc pylint_plugins.pyo

# user-facing scripts
dist_bin_SCRIPTS = ipa

# files required for build but not installed
dist_noinst_SCRIPTS = ignore_import_errors.py \
		      makeapi \
		      makeaci \
		      make-doc \
		      make-test \
		      pylint_plugins.py

ipasetup.py: ipasetup.py.in $(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@VERSION[@]|$(VERSION)|g'			\
		$< > $@

EXTRA_DIST = .mailmap \
	     ACI.txt \
	     API.txt \
	     BUILD.txt \
	     config.rpath \
	     Contributors.txt \
	     COPYING.openssl \
	     contrib \
	     doc \
	     freeipa.spec.in \
	     ipasetup.py.in \
	     pylintrc

clean-local:
	rm -rf "$(RPMBUILD)"
	rm -rf "$(top_builddir)/dist"
	rm -rf "$(top_srcdir)/__pycache__"
	rm -f "$(top_builddir)"/$(PACKAGE)-*.tar.gz


# convenience targets for RPM build
.PHONY: rpmroot rpmdistdir version-update _dist-version-bakein _rpms-prep \
	rpms _rpms-body srpms _srpms-body
RPMBUILD ?= $(abs_builddir)/rpmbuild
TARBALL = $(PACKAGE)-$(VERSION).tar.gz

freeipa.spec: freeipa.spec.in $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@VERSION[@]|$(VERSION)|g'			\
		-e 's|@VENDOR_SUFFIX[@]|$(VENDOR_SUFFIX)|g'	\
		$< > $@

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p $(top_builddir)/dist/rpms
	mkdir -p $(top_builddir)/dist/srpms

# force IPA version re-generation (useful for build from Git)
version-update:
	touch $(srcdir)/VERSION.m4

# convert Git snapshot version to static value usable from inside of tarball
_dist-version-bakein:
if !IS_GIT_SNAPSHOT
	@echo "version-bakein target requires IPA_VERSION_IS_GIT_SNAPSHOT=yes"
	exit 1
endif !IS_GIT_SNAPSHOT
	chmod u+w $(top_distdir)/VERSION.m4
	$(SED) -e 's/^define(IPA_VERSION_IS_GIT_SNAPSHOT,.*)/define(IPA_VERSION_IS_GIT_SNAPSHOT, no)/' -i $(top_distdir)/VERSION.m4
	$(SED) -e 's/^define(IPA_VERSION_PRE_RELEASE,\(.*\))/define(IPA_VERSION_PRE_RELEASE,\1.$(GIT_VERSION))/' -i $(top_distdir)/VERSION.m4
	cd $(top_distdir) && autoconf  # re-generate configure from VERSION.m4

if IS_GIT_SNAPSHOT
VERSION_UPDATE_TARGET = version-update
VERSION_BAKEIN_TARGET = _dist-version-bakein
endif IS_GIT_SNAPSHOT

# HACK to support IPA_VERSION_IS_GIT_SNAPSHOT:
# touch VERSION.m4 will reexecute configure and change $(VERSION) used by dist
# but it will not change $(VERSION) in already running target rpms.
# We need to record new $(TARBALL) value used by dist for furher use
# in rpms target.
dist-hook: $(VERSION_BAKEIN_TARGET)
	echo "$(TARBALL)" > $(top_builddir)/.tarball_name
	echo "$(VERSION)" > $(top_builddir)/.version

_rpms-prep: dist-gzip rpmroot rpmdistdir freeipa.spec
	cp $(top_builddir)/$$(cat $(top_builddir)/.tarball_name) $(RPMBUILD)/SOURCES/
	rm -f $(top_builddir)/.tarball_name

rpms: $(VERSION_UPDATE_TARGET)
	$(MAKE) _rpms-body

_rpms-body: _rpms-prep
	rpmbuild --define "_topdir $(RPMBUILD)" -ba $(top_builddir)/$(PACKAGE).spec
	cp $(RPMBUILD)/RPMS/*/*$$(cat $(top_builddir)/.version)*.rpm $(top_builddir)/dist/rpms/
	cp $(RPMBUILD)/SRPMS/*$$(cat $(top_builddir)/.version)*.src.rpm $(top_builddir)/dist/srpms/
	rm -f rm -f $(top_builddir)/.version

srpms: $(VERSION_UPDATE_TARGET)
	$(MAKE) _srpms-body

_srpms-body: _rpms-prep
	rpmbuild --define "_topdir $(RPMBUILD)" -bs $(top_builddir)/$(PACKAGE).spec
	cp $(RPMBUILD)/SRPMS/*$$(cat $(top_builddir)/.version)*.src.rpm $(top_builddir)/dist/srpms/
	rm -f rm -f $(top_builddir)/.version

.PHONY: lite-server
lite-server: $(top_builddir)/ipapython/version.py
	+$(MAKE) -C $(top_builddir)/install/ui
	PYTHONPATH=$(top_srcdir) $(PYTHON) -bb \
	    contrib/lite-server.py $(LITESERVER_ARGS)

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
acilint: $(top_builddir)/ipapython/version.py
	cd $(srcdir); ./makeaci --validate

.PHONY: apilint
apilint: $(top_builddir)/ipapython/version.py
	cd $(srcdir); ./makeapi --validate

.PHONY: polint
polint:
	$(MAKE) -C $(srcdir)/po validate-src-strings validate-po test-gettext

# Run pylint for all python files. Finds all python files/packages, skips
# folders rpmbuild, freeipa-* and dist. Skip (match, but don't print) .*,
# *.in, *~. Finally print all python files, including scripts that do not
# have python extension.
.PHONY: pylint $(top_builddir)/ipapython/version.py
$(top_builddir)/ipapython/version.py:
	(cd $(top_builddir)/ipapython && make version.py)

pylint: $(top_builddir)/ipapython/version.py ipasetup.py
	FILES=`find $(top_srcdir) \
		-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
		-path './rpmbuild' -prune -o \
		-path './freeipa-*' -prune -o \
		-path './dist' -prune -o \
		-path './pypi' -prune -o \
		-name '.*' -o \
		-name '*.in' -o \
		-name '*~' -o \
		-name '*.py' -print -o \
		-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print`; \
	echo "Pylint is running, please wait ..."; \
	PYTHONPATH=$(top_srcdir) $(PYTHON) -m pylint \
		--rcfile=$(top_srcdir)/pylintrc $${FILES}

.PHONY: jslint jslint-ui jslint-ui-test jslint-html \
	$(top_builddir)/install/ui/src/libs/loader.js
jslint: jslint-ui jslint-ui-test jslint-html

$(top_builddir)/install/ui/src/libs/loader.js:
	(cd $(top_builddir)/install/ui/src/libs && make loader.js)

# create temporary symlinks to allow jslint to find libs/loader.js
jslint-ui: $(top_builddir)/install/ui/src/libs/loader.js
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

.PHONY: bdist_wheel wheel_bundle wheel_placeholder pypi_packages
WHEELDISTDIR = $(top_builddir)/dist/wheels
WHEELBUNDLEDIR = $(top_builddir)/dist/bundle

$(WHEELDISTDIR):
	mkdir -p $(WHEELDISTDIR)

$(WHEELBUNDLEDIR):
	mkdir -p $(WHEELBUNDLEDIR)

bdist_wheel: $(WHEELDISTDIR)
	for dir in $(IPACLIENT_SUBDIRS); do \
	    $(MAKE) $(AM_MAKEFLAGS) -C $${dir} $@ || exit 1; \
	done

wheel_bundle: $(WHEELBUNDLEDIR) bdist_wheel
	$(PYTHON) -m pip wheel --wheel-dir $(WHEELBUNDLEDIR) $(WHEELDISTDIR)/*.whl

wheel_placeholder: $(WHEELDISTDIR)
	for dir in $(IPA_PLACEHOLDERS); do \
	    $(MAKE) $(AM_MAKEFLAGS) -C $(top_srcdir)/pypi/$${dir} bdist_wheel || exit 1; \
	done

pypi_packages: bdist_wheel wheel_placeholder
	@echo -e "\n\nTo upload packages to PyPI, run:\n"
	@echo -e "    twine upload $(WHEELDISTDIR)/*-$(VERSION)-py2.py3-none-any.whl\n"

.PHONY:
strip-po:
	$(MAKE) -C po strip-po
