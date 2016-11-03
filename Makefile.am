SUBDIRS = asn1 util client contrib daemons install ipaclient ipalib ipaplatform ipapython ipaserver ipatests po
# doc
# init

MOSTLYCLEANFILES = ipasetup.pyc ipasetup.pyo

# user-facing scripts
dist_bin_SCRIPTS = ipa

# files required for build but not installed
dist_noinst_SCRIPTS = ignore_import_errors.py \
		      lite-server.py \
		      makeapi \
		      makeaci \
		      make-doc \
		      make-test \
		      pylint_plugins.py

EXTRA_DIST = .mailmap \
	     ACI.txt \
	     API.txt \
	     BUILD.txt \
	     Contributors.txt \
	     COPYING.openssl \
	     contrib \
	     pylintrc \
	     pytest.ini
