NULL =

appdir = $(IPA_DATA_DIR)/ui/js/libs
app_DATA =				\
	bootstrap.js 			\
	bootstrap-datepicker.js	\
	browser.js 			\
	d3.js 			\
	jquery.js 			\
	jquery.ordered-map.js 		\
	json2.js 			\
	patternfly.js		\
	qrcode.js 			\
	$(NULL)

nodist_app_DATA =			\
	loader.js

dist_noinst_DATA =			\
	loader.js.in

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(NULL)

loader.js: loader.js.in $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@API_VERSION[@]|$(API_VERSION)|g'		\
		-e 's|@NUM_VERSION[@]|$(NUM_VERSION)|g'		\
		$< > $@
