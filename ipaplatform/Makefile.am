include $(top_srcdir)/Makefile.python.am

EXTRA_DIST = override.py.in

all-local: override.py
dist-hook: override.py
install-exec-local: override.py

override.py: override.py.in $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@IPAPLATFORM[@]|$(IPAPLATFORM)|g'		\
		$< > $@
