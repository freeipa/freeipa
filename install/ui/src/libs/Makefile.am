NULL =

UI_SRCDIR    = $(top_srcdir)/install/ui
TERSER       = $(UI_SRCDIR)/node_modules/.bin/terser
TERSER_FLAGS = --compress --mangle --comments '/^!|copyright|license/i'

appdir = $(IPA_DATA_DIR)/ui/js/libs
app_DATA =				\
	browser.js 			\
	jquery.ordered-map.js 		\
	patternfly.js			\
	qrcode.js 			\
	$(NULL)

# These four are unminified upstream sources; minified output is generated
# at build time by terser (see rules below).
nodist_app_DATA =			\
	bootstrap.js 			\
	bootstrap-datepicker.js		\
	d3.js 				\
	jquery.js 			\
	loader.js			\
	$(NULL)

EXTRA_DIST =				\
	$(app_DATA)			\
	loader.js.in			\
	upstream			\
	$(NULL)

CLEANFILES = bootstrap.js bootstrap-datepicker.js d3.js jquery.js loader.js \
             npm-terser.stamp

npm-terser.stamp: $(UI_SRCDIR)/package.json
	cd "$(UI_SRCDIR)" && npm install
	touch $@

bootstrap.js: upstream/bootstrap.js npm-terser.stamp
	$(AM_V_GEN)$(TERSER) $(TERSER_FLAGS) $< -o $@

bootstrap-datepicker.js: upstream/bootstrap-datepicker.js npm-terser.stamp
	$(AM_V_GEN)$(TERSER) $(TERSER_FLAGS) $< -o $@

d3.js: upstream/d3.js npm-terser.stamp
	$(AM_V_GEN)$(TERSER) $(TERSER_FLAGS) $< -o $@

jquery.js: upstream/jquery.js npm-terser.stamp
	$(AM_V_GEN)$(TERSER) $(TERSER_FLAGS) $< -o $@

loader.js: loader.js.in $(top_builddir)/$(CONFIG_STATUS)
	$(AM_V_GEN)sed						\
		-e 's|@API_VERSION[@]|$(API_VERSION)|g'		\
		-e 's|@NUM_VERSION[@]|$(NUM_VERSION)|g'		\
		$< > $@
