NULL =

appdir = $(IPA_DATA_DIR)/ui/js/freeipa
nodist_app_DATA =			\
	app.js 				\
	core.js 			\
	$(NULL)

CLEANFILES = $(nodist_app_DATA)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

core := $(wildcard ../../src/freeipa/*.js)
base := $(wildcard ../../src/freeipa/_base/*.js)
widgets := $(wildcard ../../src/freeipa/widgets/*.js)
nav := $(wildcard ../../src/freeipa/navigation/*.js)

app.js: $(core) $(base) $(widgets) $(nav)
	$(srcdir)/../../util/make-ui.sh

core.js: app.js
