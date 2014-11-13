/*-
 * Copyright (c) 2006 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_PER_ENCODER_H_
#define	_PER_ENCODER_H_

#include <asn_application.h>
#include <per_support.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/*
 * Unaligned PER encoder of any ASN.1 type. May be invoked by the application.
 */
asn_enc_rval_t uper_encode(struct asn_TYPE_descriptor_s *type_descriptor,
	void *struct_ptr,	/* Structure to be encoded */
	asn_app_consume_bytes_f *consume_bytes_cb,	/* Data collector */
	void *app_key		/* Arbitrary callback argument */
);

/* A variant of uper_encode() which encodes data into the existing buffer */
asn_enc_rval_t uper_encode_to_buffer(
	struct asn_TYPE_descriptor_s *type_descriptor,
	void *struct_ptr,	/* Structure to be encoded */
	void *buffer,		/* Pre-allocated buffer */
	size_t buffer_size	/* Initial buffer size (max) */
);


/*
 * Type of the generic PER encoder function.
 */
typedef asn_enc_rval_t (per_type_encoder_f)(
	struct asn_TYPE_descriptor_s *type_descriptor,
	asn_per_constraints_t *constraints,
	void *struct_ptr,
	asn_per_outp_t *per_output
);

#ifdef __cplusplus
}
#endif

#endif	/* _PER_ENCODER_H_ */
