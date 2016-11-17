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

.wheelconstraints: .wheelconstraints.in $(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@VERSION[@]|$(VERSION)|g'			\
		$< > $@

EXTRA_DIST = .mailmap \
	     ACI.txt \
	     API.txt \
	     BUILD.txt \
	     config.rpath \
	     README.md \
	     Contributors.txt \
	     COPYING.openssl \
	     contrib \
	     doc \
	     freeipa.spec.in \
	     ipasetup.py.in \
	     pylintrc \
	     .wheelconstraints.in

clean-local:
	rm -rf "$(RPMBUILD)"
	rm -rf "$(top_builddir)/dist"
	rm -rf "$(top_builddir)/.tox"
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

.PHONY: devcheck
devcheck: all
if ! WITH_POLINT
	@echo "ERROR: polint not available"; exit 1
endif
if ! WITH_PYLINT
	@echo "ERROR: pylint not available"; exit 1
endif
if ! WITH_JSLINT
	@echo "ERROR: jslint not available"; exit 1
endif
if ! WITH_PYTHON2
	@echo "ERROR: python2 not available"; exit 1
endif
	@ # run all linters, tests, and check with Python 2
	PYTHONPATH=$(top_srcdir) $(PYTHON2) ipatests/ipa-run-tests \
	    --ipaclient-unittests
	$(MAKE) $(AM_MAKEFLAGS) acilint apilint polint jslint check
	$(MAKE) $(AM_MAKEFLAGS) PYTHON=$(PYTHON2) pylint
if WITH_PYTHON3
	@ # just tests and pylint on Python 3
	PYTHONPATH=$(top_srcdir) $(PYTHON3) ipatests/ipa-run-tests \
	    --ipaclient-unittests
	$(MAKE) $(AM_MAKEFLAGS) PYTHON=$(PYTHON3) pylint
else
	@echo "WARNING: python3 not available"
endif
	@echo "All tests passed."

.PHONY: $(top_builddir)/ipapython/version.py
$(top_builddir)/ipapython/version.py:
	(cd $(top_builddir)/ipapython && make version.py)

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

.PHONY: pylint

if WITH_PYLINT
pylint: $(top_builddir)/ipapython/version.py ipasetup.py
	FILES=`find $(top_srcdir) \
		-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
		-path './rpmbuild' -prune -o \
		-path './freeipa-*' -prune -o \
		-path './dist' -prune -o \
		-path './pypi' -prune -o \
		-path './.tox' -prune -o \
		-name '.*' -o \
		-name '*.in' -o \
		-name '*~' -o \
		-name '*.py' -print -o \
		-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print`; \
	echo "Pylint on $(PYTHON) is running, please wait ..."; \
	PYTHONPATH=$(top_srcdir) $(PYTHON) -m pylint \
		--rcfile=$(top_srcdir)/pylintrc \
		--load-plugins pylint_plugins \
		$${FILES}
endif  # WITH_PYLINT

.PHONY: jslint jslint-ui jslint-ui-test jslint-html \
	$(top_builddir)/install/ui/src/libs/loader.js

if WITH_JSLINT
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
endif  # WITH_JSLINT

.PHONY: bdist_wheel wheel_bundle wheel_placeholder pypi_packages
WHEELDISTDIR = $(top_builddir)/dist/wheels
WHEELPYPIDIR = $(top_builddir)/dist/pypi
WHEELBUNDLEDIR = $(top_builddir)/dist/bundle

@MK_IFEQ@ ($(IPA_SERVER_WHEELS),1)
    IPA_WHEEL_PACKAGES @MK_ASSIGN@ $(IPACLIENT_SUBDIRS) ipaplatform ipaserver
    IPA_OMIT_INSTALL @MK_ASSIGN@ 0
@MK_ELSE@
    IPA_WHEEL_PACKAGES @MK_ASSIGN@ $(IPACLIENT_SUBDIRS)
    IPA_OMIT_INSTALL @MK_ASSIGN@ 1
@MK_ENDIF@

# additional wheels for bundle, e.g. IPA_EXTRA_WHEELS="ipatests[webui] pylint"
IPA_EXTRA_WHEELS=

$(WHEELDISTDIR):
	mkdir -p $(WHEELDISTDIR)

$(WHEELBUNDLEDIR):
	mkdir -p $(WHEELBUNDLEDIR)

$(WHEELPYPIDIR):
	mkdir -p $(WHEELPYPIDIR)

bdist_wheel: $(WHEELDISTDIR)
	rm -f $(foreach item,$(IPA_WHEEL_PACKAGES) ipatests,$(WHEELDISTDIR)/$(item)-*.whl)
	export IPA_OMIT_INSTALL=$(IPA_OMIT_INSTALL); \
	for dir in $(IPA_WHEEL_PACKAGES) ipatests; do \
	    $(MAKE) $(AM_MAKEFLAGS) -C $${dir} $@ || exit 1; \
	done

wheel_bundle: $(WHEELBUNDLEDIR) bdist_wheel .wheelconstraints
	rm -f $(foreach item,$(IPA_WHEEL_PACKAGES) ipatests,$(WHEELBUNDLEDIR)/$(item)-*.whl)
	@# dbus-python sometimes fails when MAKEFLAGS is set to -j2 or higher
	MAKEFLAGS= $(PYTHON) -m pip wheel \
	    --disable-pip-version-check \
	    --constraint .wheelconstraints \
	    --find-links $(WHEELDISTDIR) \
	    --find-links $(WHEELBUNDLEDIR) \
	    --wheel-dir $(WHEELBUNDLEDIR) \
	    $(IPA_WHEEL_PACKAGES) $(IPA_EXTRA_WHEELS)

pypi_packages: $(WHEELPYPIDIR) .wheelconstraints
	rm -f $(WHEELPYPIDIR)/*
	for dir in $(IPACLIENT_SUBDIRS); do \
	    $(MAKE) $(AM_MAKEFLAGS) \
	        IPA_OMIT_INSTALL=1 WHEELDISTDIR="$(abspath $(WHEELPYPIDIR))" \
	        -C $${dir} bdist_wheel || exit 1; \
	done
	for dir in $(IPA_PLACEHOLDERS); do \
	    $(MAKE) $(AM_MAKEFLAGS) \
	        IPA_OMIT_INSTALL=1 WHEELDISTDIR="$(abspath $(WHEELPYPIDIR))" \
	        -C $(top_srcdir)/pypi/$${dir} bdist_wheel || exit 1; \
	done
	@echo -e "\n\nTo upload packages to PyPI, run:\n"
	@echo -e "    twine upload $(WHEELPYPIDIR)/*-$(VERSION)-py2.py3-none-any.whl\n"

.PHONY:
strip-po:
	$(MAKE) -C po strip-po
