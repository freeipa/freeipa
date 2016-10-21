# IPA build system cannot cope with parallel build; disable parallel build
.NOTPARALLEL:

SUBDIRS=util asn1 daemons install ipapython ipalib
CLIENTDIRS=ipapython ipalib client util asn1
CLIENTPYDIRS=ipaclient ipaplatform
PYPKGDIRS=$(CLIENTPYDIRS) ipalib ipapython ipaserver ipatests

PRJ_PREFIX=freeipa

RPMBUILD ?= $(PWD)/rpmbuild
TARGET ?= master

# temporary hack until we replace hand-made Makefile with the generated one
IPA_VERSION=4.4.90
TARBALL_PREFIX=freeipa-$(IPA_VERSION)
TARBALL=$(TARBALL_PREFIX).tar.gz

LIBDIR ?= /usr/lib

DEVELOPER_MODE ?= 0
ifneq ($(DEVELOPER_MODE),0)
LINT_IGNORE_FAIL=true
else
LINT_IGNORE_FAIL=false
endif

PYTHON ?= $(shell rpm -E %__python || echo /usr/bin/python2)

CFLAGS := -g -O2 -Wall -Wextra -Wformat-security -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers $(CFLAGS)
export CFLAGS

# Uncomment to increase Java stack size for Web UI build in case it fails
# because of stack overflow exception. Default should be OK for most platforms.
#JAVA_STACK_SIZE ?= 8m
#export JAVA_STACK_SIZE

all: bootstrap-autogen server tests
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

# empty target to force executation
.PHONY=FORCE
FORCE:

client: bootstrap-autogen egg_info
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) all) || exit 1; \
	done
	@for subdir in $(CLIENTPYDIRS); do \
		(cd $$subdir && $(PYTHON) setup.py build); \
	done

check: bootstrap-autogen server tests
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) check) || exit 1; \
	done

client-check: bootstrap-autogen
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) check) || exit 1; \
	done

bootstrap-autogen: version-update
	@echo "Building IPA $(IPA_VERSION)"
	./autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR)

install: all server-install tests-install client-install
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

client-install: client client-dirs
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) install) || exit 1; \
	done
	cd po && $(MAKE) install || exit 1;
	@for subdir in $(CLIENTPYDIRS); do \
		if [ "$(DESTDIR)" = "" ]; then \
			(cd $$subdir && $(PYTHON) setup.py install); \
		else \
			(cd $$subdir && $(PYTHON) setup.py install --root $(DESTDIR)); \
		fi \
	done

client-dirs:
	@if [ "$(DESTDIR)" != "" ] ; then \
		mkdir -p $(DESTDIR)/etc/ipa ; \
		mkdir -p $(DESTDIR)/var/lib/ipa-client/sysrestore ; \
	else \
		echo "DESTDIR was not set, please create /etc/ipa and /var/lib/ipa-client/sysrestore" ; \
		echo "Without those directories ipa-client-install will fail" ; \
	fi

pylint: bootstrap-autogen
	# find all python modules and executable python files outside modules for pylint check
	FILES=`find . \
		-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
		-path '*/.*' -o \
		-path './dist/*' -o \
		-path './lextab.py' -o \
		-path './yacctab.py' -o \
		-name '*~' -o \
		-name \*.py -print -o \
		-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print`; \
	echo "Pylint is running, please wait ..."; \
	PYTHONPATH=. pylint --rcfile=pylintrc $(PYLINTFLAGS) $$FILES || $(LINT_IGNORE_FAIL)

po-validate:
	$(MAKE) -C po validate-src-strings || $(LINT_IGNORE_FAIL)

jslint:
	cd install/ui; jsl -nologo -nosummary -nofilelisting -conf jsl.conf || $(LINT_IGNORE_FAIL)

lint: apilint acilint pylint po-validate jslint

test:
	./make-test

ipapython/version.py: API.txt bootstrap-autogen
	grep -Po '(?<=default: ).*' API.txt | sed -n -i -e "/__DEFAULT_PLUGINS__/!{p;b};r /dev/stdin" $@
	touch -r $< $@

.PHONY: egg_info
egg_info: ipapython/version.py ipaplatform/__init__.py
	for directory in $(PYPKGDIRS); do \
	    pushd $${directory} ; \
	    $(PYTHON) setup.py egg_info $(EXTRA_SETUP); \
	    popd ; \
	done

version-update: ipapython/version.py

apilint: bootstrap-autogen
	./makeapi --validate

acilint: bootstrap-autogen
	./makeaci --validate

server: version-update bootstrap-autogen egg_info
	cd ipaserver && $(PYTHON) setup.py build
	cd ipaplatform && $(PYTHON) setup.py build

server-install: server
	if [ "$(DESTDIR)" = "" ]; then \
		(cd ipaserver && $(PYTHON) setup.py install) || exit 1; \
		(cd ipaplatform && $(PYTHON) setup.py install) || exit 1; \
	else \
		(cd ipaserver && $(PYTHON) setup.py install --root $(DESTDIR)) || exit 1; \
		(cd ipaplatform && $(PYTHON) setup.py install --root $(DESTDIR)) || exit 1; \
	fi

tests: version-update bootstrap-autogen egg_info
	cd ipatests; $(PYTHON) setup.py build
	cd ipatests/man && $(MAKE) all

tests-install: tests
	if [ "$(DESTDIR)" = "" ]; then \
		cd ipatests; $(PYTHON) setup.py install; \
	else \
		cd ipatests; $(PYTHON) setup.py install --root $(DESTDIR); \
	fi
	cd ipatests/man && $(MAKE) install

archive:
	-mkdir -p dist
	git archive --format=tar --prefix=ipa/ $(TARGET) | (cd dist && tar xf -)

local-archive:
	-mkdir -p dist/$(TARBALL_PREFIX)
	rsync -a --exclude=dist --exclude=.git --exclude=/build --exclude=rpmbuild . dist/$(TARBALL_PREFIX)

archive-cleanup:
	rm -fr dist/freeipa

tarballs: local-archive
	-mkdir -p dist/sources
	# tar up clean sources
	cd dist/$(TARBALL_PREFIX); ./autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR)
	cd dist/$(TARBALL_PREFIX)/asn1; make distclean
	cd dist/$(TARBALL_PREFIX)/daemons; make distclean
	cd dist/$(TARBALL_PREFIX)/client; make distclean
	cd dist/$(TARBALL_PREFIX)/install; make distclean
	cd dist; tar cfz sources/$(TARBALL) $(TARBALL_PREFIX)
	rm -rf dist/$(TARBALL_PREFIX)

rpmroot:
	rm -rf $(RPMBUILD)
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p dist/rpms
	mkdir -p dist/srpms

rpms: rpmroot rpmdistdir version-update lint tarballs
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba freeipa.spec
	cp $(RPMBUILD)/RPMS/*/$(PRJ_PREFIX)-*-$(IPA_VERSION)-*.rpm dist/rpms/
	cp $(RPMBUILD)/RPMS/*/python?-ipa*-$(IPA_VERSION)-*.rpm dist/rpms/
	cp $(RPMBUILD)/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)

client-rpms: rpmroot rpmdistdir version-update lint tarballs
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" --define "ONLY_CLIENT 1" -ba freeipa.spec
	cp $(RPMBUILD)/RPMS/*/$(PRJ_PREFIX)-*-$(IPA_VERSION)-*.rpm dist/rpms/
	cp $(RPMBUILD)/RPMS/*/python?-ipa*-$(IPA_VERSION)-*.rpm dist/rpms/
	cp $(RPMBUILD)/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)

srpms: rpmroot rpmdistdir version-update lint tarballs
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -bs freeipa.spec
	cp $(RPMBUILD)/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)


repodata:
	-createrepo -p dist

dist: version-update archive tarballs archive-cleanup rpms repodata

local-dist: bootstrap-autogen clean local-archive tarballs archive-cleanup rpms


clean: version-update
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -rf ipasetup.py ipasetup.py?
	rm -f *~

distclean: version-update
	touch NEWS AUTHORS ChangeLog
	touch install/NEWS install/README install/AUTHORS install/ChangeLog
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -fr $(RPMBUILD) dist build
	rm -f NEWS AUTHORS ChangeLog
	rm -f install/NEWS install/README install/AUTHORS install/ChangeLog

maintainer-clean: clean
	rm -fr $(RPMBUILD) dist build
	cd daemons && $(MAKE) maintainer-clean
	cd install && $(MAKE) maintainer-clean
	cd client && $(MAKE) maintainer-clean
	cd ipapython && $(MAKE) maintainer-clean
	rm -f version.m4
	rm -f freeipa.spec
