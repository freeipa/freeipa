SUBDIRS=ipa-server ipa-admintools ipa-python

PRJ_PREFIX=freeipa

# Version numbers - this is for the entire server. After
# updating this you should run the version-update
# target.
SERV_MAJOR=0
SERV_MINOR=1
SERV_RELEASE=0
SERV_VERSION=$(SERV_MAJOR).$(SERV_MINOR).$(SERV_RELEASE)
SERV_TARBALL_PREFIX=$(PRJ_PREFIX)-server-$(SERV_VERSION)
SERV_TARBALL=$(SERV_TARBALL_PREFIX).tgz

ADMIN_MAJOR=0
ADMIN_MINOR=1
ADMIN_RELEASE=0
ADMIN_VERSION=$(ADMIN_MAJOR).$(ADMIN_MINOR).$(ADMIN_RELEASE)
ADMIN_TARBALL_PREFIX=$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)
ADMIN_TARBALL=$(ADMIN_TARBALL_PREFIX).tgz

PYTHON_MAJOR=0
PYTHON_MINOR=1
PYTHON_RELEASE=0
PYTHON_VERSION=$(PYTHON_MAJOR).$(PYTHON_MINOR).$(PYTHON_RELEASE)
PYTHON_TARBALL_PREFIX=$(PRJ_PREFIX)-python-$(PYTHON_VERSION)
PYTHON_TARBALL=$(PYTHON_TARBALL_PREFIX).tgz

all:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

install:
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


tarballs:
	-mkdir -p dist
	hg archive -t files dist/freeipa

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

        # cleanup
	rm -fr dist/freeipa

rpm-ipa-server:
	cp dist/$(SERV_TARBALL) ~/rpmbuild/SOURCES/.
	rpmbuild -ba ipa-server/freeipa-server.spec
	cp ~/rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-server-$(SERV_VERSION)-*.rpm dist/.
	cp ~/rpmbuild/SRPMS/$(PRJ_PREFIX)-server-$(SERV_VERSION)-*.src.rpm dist/.

rpm-ipa-admin:
	cp dist/$(ADMIN_TARBALL) ~/rpmbuild/SOURCES/.
	rpmbuild -ba ipa-admintools/freeipa-admintools.spec
	cp ~/rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)-*.rpm dist/.
	cp ~/rpmbuild/SRPMS/$(PRJ_PREFIX)-admintools-$(ADMIN_VERSION)-*.src.rpm dist/.

rpm-ipa-python:
	cp dist/$(PYTHON_TARBALL) ~/rpmbuild/SOURCES/.
	rpmbuild -ba ipa-python/freeipa-python.spec
	cp ~/rpmbuild/RPMS/noarch/$(PRJ_PREFIX)-python-$(PYTHON_VERSION)-*.rpm dist/.
	cp ~/rpmbuild/SRPMS/$(PRJ_PREFIX)-python-$(PYTHON_VERSION)-*.src.rpm dist/.

rpms: rpm-ipa-server rpm-ipa-admin rpm-ipa-python

dist: version-update tarballs rpms

dist-clean: clean
	rm -fr dist
