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

ipa := $(wildcard ../less/*.less)		\
	../less/font-awesome/variables.less	\
	../less/patternfly/variables.less	\
	../less/bootstrap/variables.less	\
	../less/variables.less

ipa.css: $(ipa)
	$(srcdir)/../util/make-css.sh
