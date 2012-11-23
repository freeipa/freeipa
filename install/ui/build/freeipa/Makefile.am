NULL =

appdir = $(IPA_DATA_DIR)/ui/js/freeipa
app_DATA =				\
	app.js 				\
	$(NULL)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

MAINTAINERCLEANFILES =                  \
        *~                              \
        Makefile.in

app.js:
	../../util/make-ui.sh
