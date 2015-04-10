include VERSION

SUBDIRS=asn1 daemons install ipapython ipa-client
CLIENTDIRS=ipapython ipa-client asn1

PRJ_PREFIX=freeipa

RPMBUILD ?= $(PWD)/rpmbuild
TARGET ?= master

SUPPORTED_PLATFORM ?= fedora

IPA_NUM_VERSION ?= $(shell printf %d%02d%02d $(IPA_VERSION_MAJOR) $(IPA_VERSION_MINOR) $(IPA_VERSION_RELEASE))

# After updating the version in VERSION you should run the version-update
# target.

ifeq ($(IPA_VERSION_IS_GIT_SNAPSHOT),"yes")
DATESTR:=$(shell date -u +'%Y%m%d%H%M')
GIT_VERSION:=$(shell git show --pretty=format:"%h" --stat HEAD 2>/dev/null|head -1)
ifneq ($(GIT_VERSION),)
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE).$(DATESTR)GIT$(GIT_VERSION)
endif # in a git tree and git returned a version
endif # git

ifndef IPA_VERSION
ifdef IPA_VERSION_ALPHA_RELEASE
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE).alpha$(IPA_VERSION_ALPHA_RELEASE)
else
ifdef IPA_VERSION_BETA_RELEASE
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE).beta$(IPA_VERSION_BETA_RELEASE)
else
ifdef IPA_VERSION_RC_RELEASE
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE).rc$(IPA_VERSION_RC_RELEASE)
else
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE)
endif # rc
endif # beta
endif # alpha
endif # ipa_version

IPA_VENDOR_VERSION=$(IPA_VERSION)$(IPA_VENDOR_VERSION_SUFFIX)

TARBALL_PREFIX=freeipa-$(IPA_VERSION)
TARBALL=$(TARBALL_PREFIX).tar.gz

IPA_RPM_RELEASE=$(shell cat RELEASE)

LIBDIR ?= /usr/lib

DEVELOPER_MODE ?= 0
ifneq ($(DEVELOPER_MODE),0)
LINT_OPTIONS=--no-fail
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

client: client-autogen
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) all) || exit 1; \
	done
	cd ipaplatform && $(PYTHON) setup.py build

bootstrap-autogen: version-update client-autogen
	@echo "Building IPA $(IPA_VERSION)"
	cd asn1; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi
	cd daemons; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR) --with-openldap; fi
	cd install; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi

client-autogen: version-update
	cd asn1; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi
	cd ipa-client; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi
	cd install; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi

tests-man-autogen: version-update
	cd ipatests/man; if [ ! -e Makefile ]; then ../../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi

install: all server-install tests-install
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

client-install: client client-dirs
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) install) || exit 1; \
	done
	cd install/po && $(MAKE) install || exit 1;
	if [ "$(DESTDIR)" = "" ]; then \
		$(PYTHON) setup-client.py install; \
		(cd ipaplatform && $(PYTHON) setup.py install); \
	else \
		$(PYTHON) setup-client.py install --root $(DESTDIR); \
		(cd ipaplatform && $(PYTHON) setup.py install --root $(DESTDIR)); \
	fi

client-dirs:
	@if [ "$(DESTDIR)" != "" ] ; then \
		mkdir -p $(DESTDIR)/etc/ipa ; \
		mkdir -p $(DESTDIR)/var/lib/ipa-client/sysrestore ; \
	else \
		echo "DESTDIR was not set, please create /etc/ipa and /var/lib/ipa-client/sysrestore" ; \
		echo "Without those directories ipa-client-install will fail" ; \
	fi

lint: bootstrap-autogen
	./make-lint $(LINT_OPTIONS)
	$(MAKE) -C install/po validate-src-strings


test:
	./make-test

release-update:
	if [ ! -e RELEASE ]; then echo 0 > RELEASE; fi

version-update: release-update
	sed -e s/__VERSION__/$(IPA_VERSION)/ -e s/__RELEASE__/$(IPA_RPM_RELEASE)/ \
		freeipa.spec.in > freeipa.spec
	sed -e s/__VERSION__/$(IPA_VERSION)/ version.m4.in \
		> version.m4
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipapython/setup.py.in \
		> ipapython/setup.py
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipaplatform/setup.py.in \
		> ipaplatform/setup.py
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipapython/version.py.in \
		> ipapython/version.py
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipatests/setup.py.in \
		> ipatests/setup.py
	sed -e s/__NUM_VERSION__/$(IPA_NUM_VERSION)/ install/ui/src/libs/loader.js.in \
		> install/ui/src/libs/loader.js
	perl -pi -e "s:__API_VERSION__:$(IPA_API_VERSION_MAJOR).$(IPA_API_VERSION_MINOR):" install/ui/src/libs/loader.js
	perl -pi -e "s:__NUM_VERSION__:$(IPA_NUM_VERSION):" ipapython/version.py
	perl -pi -e "s:__VENDOR_VERSION__:$(IPA_VENDOR_VERSION):" ipapython/version.py
	perl -pi -e "s:__API_VERSION__:$(IPA_API_VERSION_MAJOR).$(IPA_API_VERSION_MINOR):" ipapython/version.py
	touch -r ipapython/version.py.in ipapython/version.py
	sed -e s/__VERSION__/$(IPA_VERSION)/ daemons/ipa-version.h.in \
		> daemons/ipa-version.h
	perl -pi -e "s:__NUM_VERSION__:$(IPA_NUM_VERSION):" daemons/ipa-version.h
	perl -pi -e "s:__DATA_VERSION__:$(IPA_DATA_VERSION):" daemons/ipa-version.h

	sed -e s/__VERSION__/$(IPA_VERSION)/ -e s/__RELEASE__/$(IPA_RPM_RELEASE)/ \
		ipa-client/ipa-client.spec.in > ipa-client/ipa-client.spec
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipa-client/version.m4.in \
		> ipa-client/version.m4

	if [ "$(SUPPORTED_PLATFORM)" != "" ]; then \
		sed -e s/__PLATFORM__/$(SUPPORTED_PLATFORM)/ \
			ipaplatform/__init__.py.in > ipaplatform/__init__.py; \
		rm -f ipaplatform/paths.py ipaplatform/services.py ipaplatform/tasks.py; \
		ln -s $(SUPPORTED_PLATFORM)/paths.py ipaplatform/paths.py; \
		ln -s $(SUPPORTED_PLATFORM)/services.py ipaplatform/services.py; \
		ln -s $(SUPPORTED_PLATFORM)/tasks.py ipaplatform/tasks.py; \
	fi

	if [ "$(SKIP_API_VERSION_CHECK)" != "yes" ]; then \
		./makeapi --validate; \
		./makeaci --validate; \
	fi

server: version-update
	$(PYTHON) setup.py build
	cd ipaplatform && $(PYTHON) setup.py build

server-install: server
	if [ "$(DESTDIR)" = "" ]; then \
		$(PYTHON) setup.py install; \
		(cd ipaplatform && $(PYTHON) setup.py install); \
	else \
		$(PYTHON) setup.py install --root $(DESTDIR); \
		(cd ipaplatform && $(PYTHON) setup.py install --root $(DESTDIR)); \
	fi

tests: version-update tests-man-autogen
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
	cd dist/$(TARBALL_PREFIX)/ipa-client; ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); make distclean
	cd dist/$(TARBALL_PREFIX)/daemons; ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); make distclean
	cd dist/$(TARBALL_PREFIX)/install; ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); make distclean
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
	cp $(RPMBUILD)/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf $(RPMBUILD)

client-rpms: rpmroot rpmdistdir version-update lint tarballs
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" --define "ONLY_CLIENT 1" -ba freeipa.spec
	cp $(RPMBUILD)/RPMS/*/$(PRJ_PREFIX)-*-$(IPA_VERSION)-*.rpm dist/rpms/
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
	rm -f *~

distclean: version-update
	touch daemons/NEWS daemons/README daemons/AUTHORS daemons/ChangeLog
	touch install/NEWS install/README install/AUTHORS install/ChangeLog
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -fr $(RPMBUILD) dist build
	rm -f daemons/NEWS daemons/README daemons/AUTHORS daemons/ChangeLog
	rm -f install/NEWS install/README install/AUTHORS install/ChangeLog

maintainer-clean: clean
	rm -fr $(RPMBUILD) dist build
	cd daemons && $(MAKE) maintainer-clean
	cd install && $(MAKE) maintainer-clean
	cd ipa-client && $(MAKE) maintainer-clean
	cd ipapython && $(MAKE) maintainer-clean
	rm -f version.m4
	rm -f freeipa.spec
