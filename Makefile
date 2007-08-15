SUBDIRS=ipa-server ipa-admintools ipa-python

PRJ_PREFIX=freeipa

RPMBUILD ?= $(PWD)/rpmbuild

# set to 1 to produce a debug build of all subprojects
#DEBUG=1

# Version numbers - this is for the entire server. After
# updating this you should run the version-update
# target.
SERV_MAJOR=0
SERV_MINOR=2
SERV_RELEASE=0
SERV_VERSION=$(SERV_MAJOR).$(SERV_MINOR).$(SERV_RELEASE)
SERV_TARBALL_PREFIX=$(PRJ_PREFIX)-server-$(SERV_VERSION)
SERV_TARBALL=$(SERV_TARBALL_PREFIX).tgz

ADMIN_MAJOR=0
ADMIN_MINOR=2
ADMIN_RELEASE=0
ADMIN_VERSION=$(ADMIN_MAJOR).$(ADMIN_MINOR).$(ADMIN_RELEASE)
ADMIN_TARBALL_PREFIX=$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)
ADMIN_TARBALL=$(ADMIN_TARBALL_PREFIX).tgz

PYTHON_MAJOR=0
PYTHON_MINOR=2
PYTHON_RELEASE=0
PYTHON_VERSION=$(PYTHON_MAJOR).$(PYTHON_MINOR).$(PYTHON_RELEASE)
PYTHON_TARBALL_PREFIX=$(PRJ_PREFIX)-python-$(PYTHON_VERSION)
PYTHON_TARBALL=$(PYTHON_TARBALL_PREFIX).tgz

ifeq ($(DEBUG),1)
	export CFLAGS = -g -Wall -Wshadow
	export LDFLAGS = -g
endif


all:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install: all
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -f *~

version-update:
	sed s/VERSION/$(SERV_VERSION)/ ipa-server/freeipa-server.spec.in \
		> ipa-server/freeipa-server.spec

	sed s/VERSION/$(ADMIN_VERSION)/ ipa-admintools/freeipa-admintools.spec.in \
		> ipa-admintools/freeipa-admintools.spec

	sed s/VERSION/$(PYTHON_VERSION)/ ipa-python/freeipa-python.spec.in \
		> ipa-python/freeipa-python.spec


archive:
	-mkdir -p dist
	hg archive -t files dist/freeipa

local-archive:
	-mkdir -p dist/freeipa
	@for subdir in $(SUBDIRS); do \
		cp -pr $$subdir dist/freeipa/.; \
	done

archive-cleanup:
	rm -fr dist/freeipa

tarballs:
        # ipa-server
	mv dist/freeipa/ipa-server dist/$(SERV_TARBALL_PREFIX)
	rm -f dist/$(SERV_TARBALL)
	cd dist; tar cfz $(SERV_TARBALL) $(SERV_TARBALL_PREFIX)
	rm -fr dist/$(SERV_TARBALL_PREFIX)

        # ipa-admintools
	mv dist/freeipa/ipa-admintools dist/$(ADMIN_TARBALL_PREFIX)
	rm -f dist/$(ADMIN_TARBALL)
	cd dist; tar cfz $(ADMIN_TARBALL) $(ADMIN_TARBALL_PREFIX)
	rm -fr dist/$(ADMIN_TARBALL_PREFIX)

        # ipa-python
	mv dist/freeipa/ipa-python dist/$(PYTHON_TARBALL_PREFIX)
	rm -f dist/$(PYTHON_TARBALL)
	cd dist; tar cfz $(PYTHON_TARBALL) $(PYTHON_TARBALL_PREFIX)
	rm -fr dist/$(PYTHON_TARBALL_PREFIX)

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpm-ipa-server:
	cp dist/$(SERV_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-server/freeipa-server.spec
	cp rpmbuild/RPMS/*/$(PRJ_PREFIX)-server-$(SERV_VERSION)-*.rpm dist/.
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-server-$(SERV_VERSION)-*.src.rpm dist/.

rpm-ipa-admin:
	cp dist/$(ADMIN_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-admintools/freeipa-admintools.spec
	cp rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)-*.rpm dist/.
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)-*.src.rpm dist/.

rpm-ipa-python:
	cp dist/$(PYTHON_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-python/freeipa-python.spec
	cp rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-python-$(PYTHON_VERSION)-*.rpm dist/.
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-python-$(PYTHON_VERSION)-*.src.rpm dist/.

rpms: rpmroot rpm-ipa-server rpm-ipa-admin rpm-ipa-python

dist: version-update archive tarballs archive-cleanup rpms

local-dist: clean version-update local-archive tarballs archive-cleanup rpms

dist-clean: clean
	rm -fr dist
