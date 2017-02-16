# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7

NULL =

pkgname = $(shell basename "$(abs_srcdir)")

# hack to handle back-in-the-hierarchy depedency on ipasetup.py
.PHONY: $(top_builddir)/ipasetup.py
$(top_builddir)/ipasetup.py:
	(cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) ipasetup.py)

DEPENDENCIES = \
	asn1				\
	client				\
	util				\
	COPYING				\
	Contributors.txt		\
	config.h			\
	ipasetup.py			\
	$(NULL)

# Python setup.py can handle symlinks to directories fine
asn1: $(top_srcdir)/asn1
	if [ ! -e "$@" ]; then ln -rs "$<"; fi

client: $(top_srcdir)/client
	if [ ! -e "$@" ]; then ln -rs "$<"; fi

util: $(top_srcdir)/util
	if [ ! -e "$@" ]; then ln -rs "$<"; fi

# On the other hand files must be copied to create proper sdist
COPYING: $(top_srcdir)/COPYING
	cp -p "$<" "$@"

Contributors.txt: $(top_srcdir)/Contributors.txt
	cp -p "$<" "$@"

ipasetup.py: $(top_builddir)/ipasetup.py
	cp -p "$<" "$@"

config.h: $(top_builddir)/config.h
	cp -p "$<" "$@"


all-local: $(DEPENDENCIES)


check-local: $(DEPENDENCIES)
	cd $(srcdir); $(PYTHON) setup.py \
		$(VERBOSITY) \
		build \
		--build-base "$(abs_builddir)/build"

clean-local: $(DEPENDENCIES)
	$(PYTHON) "$(srcdir)/setup.py" clean --all
	rm -rf "$(srcdir)/build" "$(srcdir)/dist" "$(srcdir)/MANIFEST"
	find "$(srcdir)" \
		-name "*.py[co]" -delete -o	\
		-name "__pycache__" -delete -o	\
		-name "*.egg-info" -exec rm -rf {} +
	rm -f $(DEPENDENCIES)

dist-hook: $(DEPENDENCIES)
	$(PYTHON) "$(srcdir)/setup.py" egg_info
	PYTHON_SOURCES=$$(cat "$(srcdir)/$(pkgname).egg-info/SOURCES.txt") || exit $$?;	\
	for FILEN in $${PYTHON_SOURCES}; 						\
	do										\
		if test -x "$(srcdir)/$${FILEN}"; then MODE=755; else MODE=644; fi;	\
		$(INSTALL) -D -m $${MODE} "$(srcdir)/$${FILEN}" "$(distdir)/$${FILEN}" || exit $$?;	\
	done

WHEELDISTDIR = $(top_builddir)/dist/wheels
.PHONY: sdist
sdist: $(DEPENDENCIES)
	rm -rf $(WHEELDISTDIR)/$(pkgname)*.tar.gz
	$(PYTHON) "$(srcdir)/setup.py" sdist --format=gztar --dist-dir=$(WHEELDISTDIR)
