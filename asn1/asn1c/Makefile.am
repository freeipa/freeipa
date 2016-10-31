libasn1c_la_SOURCES =		\
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
	per_opentype.c		\
	Int32.c			\
	GetKeytabControl.c	\
	GKNewKeys.c		\
	GKCurrentKeys.c		\
	GKReply.c		\
	KrbKey.c		\
	TypeValuePair.c


AM_CPPFLAGS = -I$(top_srcdir)/util

noinst_LTLIBRARIES=libasn1c.la

regenerate:
	asn1c -fskeletons-copy -fnative-types ipa.asn1
	rm -f converter-sample.c Makefile.am.sample
