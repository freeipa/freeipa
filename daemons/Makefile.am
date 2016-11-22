# This file will be processed with automake-1.7 to create Makefile.in
#
AUTOMAKE_OPTIONS = 1.7 subdir-objects

NULL =

AM_CFLAGS = $(NULL)
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
		-Wcast-align -Werror-implicit-function-declaration \
		$(NULL)
endif
export AM_CFLAGS

nodist_noinst_HEADERS = ipa-version.h
noinst_HEADERS = ipa-version.h.in

SUBDIRS =			\
	.			\
	dnssec			\
	ipa-kdb			\
	ipa-slapi-plugins	\
	ipa-sam			\
	ipa-otpd		\
	$(NULL)

ipa-version.h: ipa-version.h.in $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@DATA_VERSION[@]|$(DATA_VERSION)|g'	\
		-e 's|@NUM_VERSION[@]|$(NUM_VERSION)|g'		\
		-e 's|@VERSION[@]|$(VERSION)|g'			\
		$< > $@
