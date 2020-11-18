NULL =

AUTOMAKE_OPTIONS = 1.7 subdir-objects

AM_CPPFLAGS = $(CRYPTO_CFLAGS) $(KRB5_CFLAGS) $(LDAP_CFLAGS) $(PWQUALITY_CFLAGS)

noinst_LTLIBRARIES = libutil.la

libutil_la_SOURCES = \
			ipa_hostname.c \
			ipa_hostname.h \
			ipa_krb5.c \
			ipa_krb5.h \
			ipa_mspac.h \
			ipa_ldap.c \
			ipa_ldap.h \
			ipa_pwd.c \
			ipa_pwd.h \
			ipa_pwd_ntlm.c \
			$(NULL)

libutil_la_LIBADD = $(CRYPTO_LIBS) $(KRB5_LIBS) $(LDAP_LIBS) $(PWQUALITY_LIBS)

check_PROGRAMS = t_pwd
t_pwd_LDADD = libutil.la
if ENABLE_SERVER
check_PROGRAMS += t_policy
t_policy_LDADD = libutil.la
endif

TESTS = $(check_PROGRAMS)
