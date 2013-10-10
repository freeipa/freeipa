NULL =

appdir = $(IPA_DATA_DIR)/ui/css
app_DATA =				\
	bootstrap.css 			\
	rcue.css 			\
	$(NULL)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

MAINTAINERCLEANFILES =                  \
        *~                              \
        Makefile.in

rcue := $(wildcard ../less/*.less)

rcue.css: $(rcue)
	../util/make-css.sh