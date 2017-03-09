include $(top_srcdir)/Makefile.python.am

MOSTLYCLEANFILES = .DEFAULT_PLUGINS

EXTRA_DIST = version.py.in

all-local: version.py
dist-hook: version.py
install-exec-local: version.py
bdist_wheel: version.py

.DEFAULT_PLUGINS: $(top_srcdir)/API.txt
	$(AM_V_GEN)awk '$$1 == "default:" { print $$2 }' $< >$@

version.py: version.py.in .DEFAULT_PLUGINS $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@API_VERSION[@]|$(API_VERSION)|g'		\
		-e 's|@NUM_VERSION[@]|$(NUM_VERSION)|g'		\
		-e 's|@VERSION[@]|$(VERSION)|g'			\
		-e 's|@VENDOR_SUFFIX[@]|$(VENDOR_SUFFIX)|g'	\
		-e '/@DEFAULT_PLUGINS[@]/r .DEFAULT_PLUGINS'	\
		-e '/@DEFAULT_PLUGINS[@]/d'			\
		$< > $@
