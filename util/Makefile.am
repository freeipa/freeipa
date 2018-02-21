AUTOMAKE_OPTIONS = 1.7 subdir-objects

AM_CPPFLAGS = $(CRYPTO_CFLAGS) $(KRB5_CFLAGS) $(LDAP_CFLAGS) $(NSS_CFLAGS)

noinst_LTLIBRARIES = libutil.la

libutil_la_SOURCES =	ipa_krb5.c \
			ipa_krb5.h \
			ipa_mspac.h \
			ipa_ldap.c \
			ipa_ldap.h \
			ipa_pwd.c \
			ipa_pwd.h \
			ipa_pwd_ntlm.c

libutil_la_LIBADD = $(CRYPTO_LIBS) $(KRB5_LIBS) $(LDAP_LIBS) $(NSS_LIBS)
