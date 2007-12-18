PLUGINS_SHARE = $(DESTDIR)/usr/share/ipa/plugins
PLUGINS_PYTHON = $(DESTDIR)/usr/share/ipa/ipaserver/plugins
SBINDIR = $(DESTDIR)/usr/sbin

all:

install:
	-mkdir -p $(PLUGINS_SHARE)
	-mkdir -p $(PLUGINS_PYTHON)
	-mkdir -p $(PLUGINS_SBINDIR)
	install -m 644 plugins/*.py $(PLUGINS_PYTHON)
	install -m 644 share/*.template $(PLUGINS_SHARE)
	install -m 755 ipa-radius-install $(SBINDIR)

clean:
	rm -fr *.pyc *~

distclean: clean

test: