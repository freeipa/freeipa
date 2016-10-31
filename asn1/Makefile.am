SUBDIRS = asn1c

AM_CPPFLAGS = -I$(top_srcdir)/util -I$(srcdir)/asn1c

noinst_LTLIBRARIES=libipaasn1.la
noinst_HEADERS=ipa_asn1.h
libipaasn1_la_SOURCES=ipa_asn1.c
libipaasn1_la_LIBADD=asn1c/libasn1c.la
