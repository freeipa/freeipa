SHAREDIR=$(DESTDIR)/usr/share/ipa
SBINDIR=$(DESTDIR)/usr/sbin
INITDIR = $(DESTDIR)/etc/rc.d/init.d

IPAGUI_SUBDIRS=config forms helpers templates
STATIC_SUBDIRS=css images javascript

all: ;

install:
	-mkdir -p $(SHAREDIR)/ipagui
	install -m 644 ipagui/*.py $(SHAREDIR)/ipagui

	-mkdir -p $(SHAREDIR)/ipa_gui.egg-info
	install -m 644 ipa_gui.egg-info/* $(SHAREDIR)/ipa_gui.egg-info

	@for subdir in $(IPAGUI_SUBDIRS); do \
		mkdir -p $(SHAREDIR)/ipagui/$$subdir; \
		install -m 644 ipagui/$$subdir/*.py $(SHAREDIR)/ipagui/$$subdir; \
	done

	install -m 644 ipagui/config/*.cfg $(SHAREDIR)/ipagui/config

	-mkdir -p $(SHAREDIR)/ipagui/static
	@for subdir in $(STATIC_SUBDIRS); do \
		mkdir -p $(SHAREDIR)/ipagui/static/$$subdir; \
		install -m 644 ipagui/static/$$subdir/* $(SHAREDIR)/ipagui/static/$$subdir; \
	done

	install -m 644 ipa-webgui.cfg $(SHAREDIR)

	install -m 755 ipa-webgui $(SBINDIR)

	-mkdir -p $(INITDIR)
	install -m 755 ipa-webgui.init $(INITDIR)/ipa-webgui

clean:
	find . -name "*.pyc" -exec rm -f {} \;
	find . -name "*~" -exec rm -f {} \;
