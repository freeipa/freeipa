include $(top_srcdir)/Makefile.python.am

EXTRA_DIST = version.py.in

all-local: version.py
dist-hook: version.py
install-exec-local: version.py
bdist_wheel: version.py

version.py: version.py.in $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@API_VERSION[@]|$(API_VERSION)|g'		\
		-e 's|@NUM_VERSION[@]|$(NUM_VERSION)|g'		\
		-e 's|@VERSION[@]|$(VERSION)|g'			\
		-e 's|@VENDOR_SUFFIX[@]|$(VENDOR_SUFFIX)|g'	\
		$< > $@
