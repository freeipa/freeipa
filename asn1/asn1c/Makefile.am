NULL =

ASN1C_SOURCES =			\
	INTEGER.c		\
	NativeEnumerated.c	\
	NativeInteger.c		\
	asn_SEQUENCE_OF.c	\
	asn_SET_OF.c		\
	constr_CHOICE.c		\
	constr_SEQUENCE.c	\
	constr_SEQUENCE_OF.c	\
	constr_SET_OF.c		\
	OCTET_STRING.c		\
	BIT_STRING.c		\
	asn_codecs_prim.c	\
	ber_tlv_length.c	\
	ber_tlv_tag.c		\
	ber_decoder.c		\
	der_encoder.c		\
	constr_TYPE.c		\
	constraints.c		\
	xer_support.c		\
	xer_decoder.c		\
	xer_encoder.c		\
	per_support.c		\
	per_decoder.c		\
	per_encoder.c		\
	$(NULL)

ASN1C_HEADERS =
	INTEGER.h		\
	NativeEnumerated.h	\
	NativeInteger.h		\
	asn_SEQUENCE_OF.h	\
	asn_SET_OF.h		\
	constr_CHOICE.h		\
	constr_SEQUENCE.h	\
	constr_SEQUENCE_OF.h	\
	constr_SET_OF.h		\
	asn_application.h	\
	asn_system.h		\
	asn_codecs.h		\
	asn_internal.h		\
	OCTET_STRING.h		\
	BIT_STRING.h		\
	asn_codecs_prim.h	\
	ber_tlv_length.h	\
	ber_tlv_tag.h		\
	ber_decoder.h		\
	der_encoder.h		\
	constr_TYPE.h		\
	constraints.h		\
	xer_support.h		\
	xer_decoder.h		\
	xer_encoder.h		\
	per_support.h		\
	per_decoder.h		\
	per_encoder.h		\
	$(NULL)

ASN1Cdir = .

IPAASN1_SOURCES=		\
	Int32.c			\
	GetKeytabControl.c	\
	GKNewKeys.c		\
	GKCurrentKeys.c		\
	GKReply.c		\
	KrbKey.c		\
	TypeValuePair.c		\
	$(NULL)

IPAASN1_HEADERS=		\
	Int32.h			\
	GetKeytabControl.h	\
	GKNewKeys.h		\
	GKCurrentKeys.h		\
	GKReply.h		\
	KrbKey.h		\
	TypeValuePair.h		\
	$(NULL)

IPAASN1dir = .

AM_CPPFLAGS = -I../../util

noinst_LTLIBRARIES=libasn1c.la
noinst_HEADERS=$(ASN1C_HEADERS) $(IPAASN1_HEADERS)
libasn1c_la_SOURCES=$(ASN1C_SOURCES) $(IPAASN1_SOURCES)

regenerate:
	asn1c -fskeletons-copy -fnative-types ipa.asn1
	rm -f converter-sample.c Makefile.am.sample
