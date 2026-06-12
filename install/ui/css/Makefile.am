NULL =

appdir = $(IPA_DATA_DIR)/ui/css
app_DATA =				\
	bootstrap-datepicker3.min.css	\
	bootstrap3-compat.css		\
	bootstrap5-transition.css	\
	patternfly.css 			\
	$(NULL)

nodist_app_DATA =			\
	ipa.css

# PatternFly 6 font assets
fonttextdir   = $(IPA_DATA_DIR)/ui/css/assets/fonts/RedHatText
fonttext_DATA = \
	assets/fonts/RedHatText/RedHatTextVF.woff2		\
	assets/fonts/RedHatText/RedHatTextVF-Italic.woff2	\
	$(NULL)

fontdisplaydir   = $(IPA_DATA_DIR)/ui/css/assets/fonts/RedHatDisplay
fontdisplay_DATA = \
	assets/fonts/RedHatDisplay/RedHatDisplayVF.woff2		\
	assets/fonts/RedHatDisplay/RedHatDisplayVF-Italic.woff2	\
	$(NULL)

fontmonodir   = $(IPA_DATA_DIR)/ui/css/assets/fonts/RedHatMono
fontmono_DATA = \
	assets/fonts/RedHatMono/RedHatMonoVF.woff2		\
	assets/fonts/RedHatMono/RedHatMonoVF-Italic.woff2	\
	$(NULL)

fontfadir   = $(IPA_DATA_DIR)/ui/css/assets/fonts/webfonts
fontfa_DATA = \
	assets/fonts/webfonts/fa-solid-900.woff2	\
	$(NULL)

fonticondir   = $(IPA_DATA_DIR)/ui/css/assets/pficon
fonticon_DATA = \
	assets/pficon/pf-v6-pficon.woff2	\
	$(NULL)

CLEANFILES = $(nodist_app_DATA)

EXTRA_DIST =                            \
        $(app_DATA)                     \
        $(fonttext_DATA)                \
        $(fontdisplay_DATA)             \
        $(fontmono_DATA)                \
        $(fontfa_DATA)                  \
        $(fonticon_DATA)                \
        $(NULL)

ipa := \
    $(wildcard ../less/*.less)		\
    $(wildcard ../less/*/*.less)		\
	$(NULL)

ipa.css: $(ipa)
	$(PYTHON) -m lesscpy -x ../less/ipa.less > $@
