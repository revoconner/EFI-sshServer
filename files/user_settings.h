/* wolfCrypt configuration for the freestanding UEFI build. Only what the SSH transport needs: curve25519, ed25519, AES-CTR, HMAC-SHA2, Hash DRBG. */

#ifndef WOLF_USER_SETTINGS_H_
#define WOLF_USER_SETTINGS_H_

#include <stddef.h>

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_NO_SOCK
#define NO_ASN_TIME
#define NO_ASN
#define NO_CERTS
#define NO_SIG_WRAPPER
#define NO_ERROR_STRINGS
#define NO_WOLFSSL_MEMORY
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_NO_ASM
#define NO_GETENV

#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_RC4
#define NO_PWDBASED
#define NO_PSK
#define NO_OLD_TLS
#define NO_PKCS8
#define NO_PKCS12
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_HMAC_ASN

#define HAVE_CURVE25519
#define HAVE_ED25519
#define HAVE_ED25519_SIGN
#define HAVE_ED25519_VERIFY
#define HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_EXPORT
#define HAVE_ED25519_MAKE_KEY
#define WOLFSSL_SHA512
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_HASHDRBG

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Heap goes through UEFI AllocatePool, see uefirt.c. */
#define XMALLOC_USER

/* Entropy from the firmware RNG protocol or RDRAND, see uefirt.c. */
extern int UefiRandSeed(unsigned char *out, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED UefiRandSeed

#endif
