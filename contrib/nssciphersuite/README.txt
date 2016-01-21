Cipher suite for mod_nss
------------------------

The nssciphersuite.py script parses mod_nss' nss_engine_cipher.c file and
creates a list of secure cipher suites for TLS. The script filters out
insecure, obsolete and slow ciphers according to some rules.

As of January 2016 and mod_nss 1.0.12 the cipher suite list contains 14
cipher suites for TLS 1.0, 1.1 and 1.2 for RSA and ECDSA certificates. The
cipher suite list also supports Perfect Forward Secrecy with ephemeral ECDH
key exchange. https://www.ssllabs.com/ gives a 'A' grade.

Note:
No suite is compatible with IE 8 and earlier on Windows XP. If you need IE 8
support, append "+rsa_3des_sha" to enable TLS_RSA_WITH_3DES_EDE_CBC_SHA.

# disabled cipher attributes: SSL_3DES, SSL_CAMELLIA, SSL_CAMELLIA128, SSL_CAMELLIA256, SSL_DES, SSL_DSS, SSL_MD5, SSL_RC2, SSL_RC4, SSL_aDSS, SSL_aNULL, SSL_eNULL, SSL_kECDHe, SSL_kECDHr, kECDH
# weak strength: SSL_EXPORT40, SSL_EXPORT56, SSL_LOW, SSL_STRONG_NONE
# enabled cipher suites:
#   TLS_RSA_WITH_AES_128_CBC_SHA256
#   TLS_RSA_WITH_AES_256_CBC_SHA256
#   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#   TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
#   TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
#   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#   TLS_RSA_WITH_AES_128_GCM_SHA256
#   TLS_RSA_WITH_AES_128_CBC_SHA
#   TLS_RSA_WITH_AES_256_GCM_SHA384
#   TLS_RSA_WITH_AES_256_CBC_SHA
#

NSSCipherSuite +aes_128_sha_256,+aes_256_sha_256,+ecdhe_ecdsa_aes_128_gcm_sha_256,+ecdhe_ecdsa_aes_128_sha,+ecdhe_ecdsa_aes_256_gcm_sha_384,+ecdhe_ecdsa_aes_256_sha,+ecdhe_rsa_aes_128_gcm_sha_256,+ecdhe_rsa_aes_128_sha,+ecdhe_rsa_aes_256_gcm_sha_384,+ecdhe_rsa_aes_256_sha,+rsa_aes_128_gcm_sha_256,+rsa_aes_128_sha,+rsa_aes_256_gcm_sha_384,+rsa_aes_256_sha
