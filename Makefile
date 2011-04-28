include VERSION

SUBDIRS=daemons install ipapython ipa-client
CLIENTDIRS=ipapython ipa-client

PRJ_PREFIX=freeipa

RPMBUILD ?= $(PWD)/rpmbuild
TARGET ?= master

# After updating the version in VERSION you should run the version-update
# target.

ifeq ($(IPA_VERSION_IS_GIT_SNAPSHOT),"yes")
GIT_VERSION=$(shell git show --pretty=format:"%h" --stat HEAD 2>/dev/null|head -1)
ifneq ($(GIT_VERSION),)
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE)GIT$(GIT_VERSION)
endif # in a git tree and git returned a version
endif # git

ifndef IPA_VERSION
ifdef IPA_VERSION_PRE_RELEASE
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE).pre$(IPA_VERSION_PRE_RELEASE)
else
ifdef IPA_VERSION_RC_RELEASE
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE).rc$(IPA_VERSION_RC_RELEASE)
else
IPA_VERSION=$(IPA_VERSION_MAJOR).$(IPA_VERSION_MINOR).$(IPA_VERSION_RELEASE)
endif # rc
endif # pre
endif # ipa_version

TARBALL_PREFIX=freeipa-$(IPA_VERSION)
TARBALL=$(TARBALL_PREFIX).tar.gz

IPA_RPM_RELEASE=$(shell cat RELEASE)

LIBDIR ?= /usr/lib

DEVELOPER_MODE ?= 0
ifneq ($(DEVELOPER_MODE),0)
LINT_OPTIONS=--no-fail
endif

all: bootstrap-autogen server
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

client: client-autogen
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) all) || exit 1; \
	done

bootstrap-autogen: version-update client-autogen
	@echo "Building IPA $(IPA_VERSION)"
	cd daemons; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR) --with-openldap; fi
	cd install; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi

client-autogen: version-update
	cd ipa-client; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi
	cd install; if [ ! -e Makefile ]; then ../autogen.sh --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=$(LIBDIR); fi

install: all server-install
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

client-install: client
	@for subdir in $(CLIENTDIRS); do \
		(cd $$subdir && $(MAKE) install) || exit 1; \
	done
	cd install/po && $(MAKE) install || exit 1;
	if [ "$(DESTDIR)" = "" ]; then \
		python setup-client.py install; \
	else \
		python setup-client.py install --root $(DESTDIR); \
	fi

lint:
	./make-lint $(LINT_OPTIONS)

test:
	$(MAKE) -C install/po test_lang
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
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipapython/version.py.in \
		> ipapython/version.py
	perl -pi -e "s:__NUM_VERSION__:$(IPA_VERSION_MAJOR)$(IPA_VERSION_MINOR)$(IPA_VERSION_RELEASE):" ipapython/version.py
	perl -pi -e "s:__API_VERSION__:$(IPA_API_VERSION_MAJOR).$(IPA_API_VERSION_MINOR):" ipapython/version.py
	sed -e s/__VERSION__/$(IPA_VERSION)/ daemons/ipa-version.h.in \
		> daemons/ipa-version.h
	perl -pi -e "s:__NUM_VERSION__:$(IPA_VERSION_MAJOR)$(IPA_VERSION_MINOR)$(IPA_VERSION_RELEASE):" daemons/ipa-version.h
	perl -pi -e "s:__DATA_VERSION__:$(IPA_DATA_VERSION):" daemons/ipa-version.h

	sed -e s/__VERSION__/$(IPA_VERSION)/ -e s/__RELEASE__/$(IPA_RPM_RELEASE)/ \
		ipa-client/ipa-client.spec.in > ipa-client/ipa-client.spec
	sed -e s/__VERSION__/$(IPA_VERSION)/ ipa-client/version.m4.in \
		> ipa-client/version.m4
	if [ "$(SKIP_API_VERSION_CHECK)" != "yes" ]; then \
		./makeapi --validate; \
	fi

server:
	python setup.py build

server-install: server
	if [ "$(DESTDIR)" = "" ]; then \
		python setup.py install; \
	else \
		python setup.py install --root $(DESTDIR); \
	fi

archive:
	-mkdir -p dist
	git archive --format=tar --prefix=ipa/ $(TARGET) | (cd dist && tar xf -)

local-archive:
	-mkdir -p dist/$(TARBALL_PREFIX)
	rsync -a --exclude=dist --exclude=.git --exclude=build --exclude=rpmbuild . dist/$(TARBALL_PREFIX)

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
	cp rpmbuild/RPMS/*/$(PRJ_PREFIX)-*-$(IPA_VERSION)-*.rpm dist/rpms/
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf rpmbuild

client-rpms: rpmroot rpmdistdir version-update lint tarballs
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" --define "ONLY_CLIENT 1" -ba freeipa.spec
	cp rpmbuild/RPMS/*/$(PRJ_PREFIX)-*-$(IPA_VERSION)-*.rpm dist/rpms/
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf rpmbuild

srpms: rpmroot rpmdistdir version-update lint tarballs
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -bs freeipa.spec
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-$(IPA_VERSION)-*.src.rpm dist/srpms/
	rm -rf rpmbuild


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
	rm -fr rpmbuild dist build
	rm -f daemons/NEWS daemons/README daemons/AUTHORS daemons/ChangeLog
	rm -f install/NEWS install/README install/AUTHORS install/ChangeLog

maintainer-clean: clean
	rm -fr rpmbuild dist build
	cd selinux && $(MAKE) maintainer-clean
	cd daemons && $(MAKE) maintainer-clean
	cd install && $(MAKE) maintainer-clean
	cd ipa-client && $(MAKE) maintainer-clean
	cd ipapython && $(MAKE) maintainer-clean
	rm -f version.m4
	rm -f freeipa.spec
