SELINUXTYPE = targeted
NULL =

if BUILD_SELINUX_POLICY
MODULE = ipa.pp.bz2
MODULE_IF = ipa.if
else
MODULE =
MODULE_IF =
endif

dist_noinst_DATA =	\
	ipa.fc			\
	ipa.if			\
	ipa.te			\
	$(NULL)

# selinuxincludedir = $(datarootdir)/selinux/devel/include/contrib
# nodist_selinuxinclude_DATA = \
#	$(MODULE_IF)			\
#	$(NULL)

selinuxpolicydir = $(datarootdir)/selinux/packages/$(SELINUXTYPE)
nodist_selinuxpolicy_DATA =	\
	$(MODULE)				\
	$(NULL)

%.pp.bz2: %.pp
	bzip2 -f -9 $^

%.pp: %.te %.fc %.if
	make -f $(selinux_makefile) $@

clean-local:
	rm -f *~  *.tc *.pp *.pp.bz2
