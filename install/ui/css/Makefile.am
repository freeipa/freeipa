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

ipa := \
    $(wildcard ../less/*.less)		\
    $(wildcard ../less/*/*.less)		\
	$(NULL)

ipa.css: $(ipa)
	$(PYTHON) -m lesscpy -x ../less/ipa.less > $@
