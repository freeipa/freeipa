SUBDIRS = ipa_webgui ipa_kpasswd
POLICY_MAKEFILE = /usr/share/selinux/devel/Makefile
POLICY_DIR = $(DESTDIR)/usr/share/selinux/targeted

all:
	if [ ! -e $(POLICY_MAKEFILE) ]; then echo "You need to install the SELinux development tools (selinux-policy-devel)" && exit 1; fi

	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) -f $(POLICY_MAKEFILE) $@) || exit 1; \
	done

clean:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) -f $(POLICY_MAKEFILE) $@) || exit 1; \
	done

distclean: clean
	rm -f ipa-server-selinux.spec

maintainer-clean: distclean

install: all
	install -d $(POLICY_DIR)
	install -m 644 ipa_webgui/ipa_webgui.pp $(POLICY_DIR)
	install -m 644 ipa_kpasswd/ipa_kpasswd.pp $(POLICY_DIR)

load:
	/usr/sbin/semodule -i ipa_webgui/ipa_webgui.pp ipa_kpasswd/ipa_kpasswd.pp
