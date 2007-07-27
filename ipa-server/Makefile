SUBDIRS=ipa-install

# Version number - this is for the entire server. After
# updating this you should run the version-update
# target.
MAJOR=0
MINOR=1
RELEASE=0
VERSION=$(MAJOR).$(MINOR).$(RELEASE)

TARBALL_PREFIX=freeipa-server-$(VERSION)
TARBALL=$(TARBALL_PREFIX).tgz

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

version-update:
	sed s/VERSION/$(VERSION)/ freeipa-server.spec.in > freeipa-server.spec

tarball:
	-mkdir dist
	hg archive -p $(TARBALL_PREFIX) -t tgz dist/$(TARBALL)

dist: version-update tarball
	cp dist/$(TARBALL) ~/rpmbuild/SOURCES/.
	rpmbuild -ba freeipa-server.spec
	cp ~/rpmbuild/RPMS/noarch/freeipa-server-$(VERSION)-*.rpm dist/.
	cp ~/rpmbuild/SRPMS/freeipa-server-$(VERSION)-*.src.rpm dist/.
