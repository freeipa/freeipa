NULL =

appdir = $(IPA_DATA_DIR)/ui/css
app_DATA =				\
	bootstrap-datepicker3.min.css	\
	patternfly.css 			\
	ipa.css 			\
	$(NULL)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

MAINTAINERCLEANFILES =                  \
        *~                              \
        Makefile.in

ipa := $(wildcard ../less/*.less)

ipa.css: $(ipa)
	../util/make-css.sh