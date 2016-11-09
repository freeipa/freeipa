NULL =

appdir = $(IPA_DATA_DIR)/ui/css
app_DATA =				\
	bootstrap-datepicker3.min.css	\
	patternfly.css 			\
	$(NULL)

nodist_app_DATA =			\
	ipa.css

CLEANFILES = $(nodist_app_DATA)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

MAINTAINERCLEANFILES =                  \
        *~                              \
        Makefile.in

ipa := $(wildcard ../less/*.less)

ipa.css: $(ipa)
	$(srcdir)/../util/make-css.sh
