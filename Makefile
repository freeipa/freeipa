SUBDIRS=ipa-server ipa-admintools ipa-python ipa-client

PRJ_PREFIX=ipa

RPMBUILD ?= $(PWD)/rpmbuild

# Version numbers - this is for the entire server. After
# updating this you should run the version-update
# target.
SERV_MAJOR=0
SERV_MINOR=5
SERV_RELEASE=0
SERV_VERSION=$(SERV_MAJOR).$(SERV_MINOR).$(SERV_RELEASE)
SERV_TARBALL_PREFIX=$(PRJ_PREFIX)-server-$(SERV_VERSION)
SERV_TARBALL=$(SERV_TARBALL_PREFIX).tgz

ADMIN_MAJOR=0
ADMIN_MINOR=5
ADMIN_RELEASE=0
ADMIN_VERSION=$(ADMIN_MAJOR).$(ADMIN_MINOR).$(ADMIN_RELEASE)
ADMIN_TARBALL_PREFIX=$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)
ADMIN_TARBALL=$(ADMIN_TARBALL_PREFIX).tgz

PYTHON_MAJOR=0
PYTHON_MINOR=5
PYTHON_RELEASE=0
PYTHON_VERSION=$(PYTHON_MAJOR).$(PYTHON_MINOR).$(PYTHON_RELEASE)
PYTHON_TARBALL_PREFIX=$(PRJ_PREFIX)-python-$(PYTHON_VERSION)
PYTHON_TARBALL=$(PYTHON_TARBALL_PREFIX).tgz

CLI_MAJOR=0
CLI_MINOR=5
CLI_RELEASE=0
CLI_VERSION=$(CLI_MAJOR).$(CLI_MINOR).$(CLI_RELEASE)
CLI_TARBALL_PREFIX=$(PRJ_PREFIX)-client-$(CLI_VERSION)
CLI_TARBALL=$(CLI_TARBALL_PREFIX).tgz

LIBDIR ?= /usr/lib

all: bootstrap-autogen
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

bootstrap-autogen:
	cd ipa-server; if [ ! -e Makefile ]; then ./autogen.sh --prefix=/usr --sysconfdir=/etc --libdir=$(LIBDIR); fi
	cd ipa-client; if [ ! -e Makefile ]; then ./autogen.sh --prefix=/usr --sysconfdir=/etc --libdir=$(LIBDIR); fi

autogen:
	cd ipa-server; ./autogen.sh --prefix=/usr --sysconfdir=/etc --libdir=$(LIBDIR)
	cd ipa-client; ./autogen.sh --prefix=/usr --sysconfdir=/etc --libdir=$(LIBDIR)

configure:
	cd ipa-server; ./configure --prefix=/usr --sysconfdir=/etc
	cd ipa-client; ./configure --prefix=/usr --sysconfdir=/etc

install: all
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

version-update:
	sed s/VERSION/$(SERV_VERSION)/ ipa-server/ipa-server.spec.in \
		> ipa-server/ipa-server.spec

	sed s/VERSION/$(ADMIN_VERSION)/ ipa-admintools/ipa-admintools.spec.in \
		> ipa-admintools/ipa-admintools.spec

	sed s/VERSION/$(PYTHON_VERSION)/ ipa-python/ipa-python.spec.in \
		> ipa-python/ipa-python.spec

	sed s/VERSION/$(CLI_VERSION)/ ipa-client/ipa-client.spec.in \
		> ipa-client/ipa-client.spec


archive:
	-mkdir -p dist
	hg archive -t files dist/ipa

local-archive:
	-mkdir -p dist/ipa
	@for subdir in $(SUBDIRS); do \
		cp -pr $$subdir dist/ipa/.; \
	done

archive-cleanup:
	rm -fr dist/ipa

tarballs:
	-mkdir -p dist/sources

        # ipa-server
	mv dist/ipa/ipa-server dist/$(SERV_TARBALL_PREFIX)
	rm -f dist/sources/$(SERV_TARBALL)
	cd dist/$(SERV_TARBALL_PREFIX); ./autogen.sh; make distclean
	cd dist; tar cfz sources/$(SERV_TARBALL) $(SERV_TARBALL_PREFIX)
	rm -fr dist/$(SERV_TARBALL_PREFIX)

        # ipa-admintools
	mv dist/ipa/ipa-admintools dist/$(ADMIN_TARBALL_PREFIX)
	rm -f dist/sources/$(ADMIN_TARBALL)
	cd dist; tar cfz sources/$(ADMIN_TARBALL) $(ADMIN_TARBALL_PREFIX)
	rm -fr dist/$(ADMIN_TARBALL_PREFIX)

        # ipa-python
	mv dist/ipa/ipa-python dist/$(PYTHON_TARBALL_PREFIX)
	rm -f dist/sources/$(PYTHON_TARBALL)
	cd dist; tar cfz sources/$(PYTHON_TARBALL) $(PYTHON_TARBALL_PREFIX)
	rm -fr dist/$(PYTHON_TARBALL_PREFIX)

        # ipa-client
	mv dist/ipa/ipa-client dist/$(CLI_TARBALL_PREFIX)
	rm -f dist/sources/$(CLI_TARBALL)
	cd dist/$(CLI_TARBALL_PREFIX); ./autogen.sh; make distclean
	cd dist; tar cfz sources/$(CLI_TARBALL) $(CLI_TARBALL_PREFIX)
	rm -fr dist/$(CLI_TARBALL_PREFIX)

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p dist/rpms
	mkdir -p dist/srpms

rpm-ipa-server:
	cp dist/sources/$(SERV_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-server/ipa-server.spec
	cp rpmbuild/RPMS/*/$(PRJ_PREFIX)-server-$(SERV_VERSION)-*.rpm dist/rpms/
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-server-$(SERV_VERSION)-*.src.rpm dist/srpms/

rpm-ipa-admin:
	cp dist/sources/$(ADMIN_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-admintools/ipa-admintools.spec
	cp rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)-*.rpm dist/rpms/
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)-*.src.rpm dist/srpms/

rpm-ipa-python:
	cp dist/sources/$(PYTHON_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-python/ipa-python.spec
	cp rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-python-$(PYTHON_VERSION)-*.rpm dist/rpms/
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-python-$(PYTHON_VERSION)-*.src.rpm dist/srpms/

rpm-ipa-client:
	cp dist/sources/$(CLI_TARBALL) $(RPMBUILD)/SOURCES/.
	rpmbuild --define "_topdir $(RPMBUILD)" -ba ipa-client/ipa-client.spec
	cp rpmbuild/RPMS/*/$(PRJ_PREFIX)-client-$(CLI_VERSION)-*.rpm dist/rpms/
	cp rpmbuild/SRPMS/$(PRJ_PREFIX)-client-$(CLI_VERSION)-*.src.rpm dist/srpms/

rpms: rpmroot rpmdistdir rpm-ipa-server rpm-ipa-admin rpm-ipa-python rpm-ipa-client

repodata:
	-createrepo -p dist

dist: version-update archive tarballs archive-cleanup rpms repodata

local-dist: autogen clean version-update local-archive tarballs archive-cleanup rpms


clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -f *~

distclean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
	rm -fr rpmbuild dist

maintainer-clean: clean
	rm -fr rpmbuild dist
	cd ipa-server && $(MAKE) maintainer-clean
	cd ipa-client && $(MAKE) maintainer-clean
	cd ipa-python && $(MAKE) maintainer-clean
