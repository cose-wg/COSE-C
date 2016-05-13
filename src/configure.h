//
//  Define which AES GCM algorithms are being used
//

#define USE_AES_GCM_128
#define USE_AES_GCM_192
#define USE_AES_GCM_256

#if defined(USE_AES_GCM_128) || defined(USE_AES_GCM_192) || defined(USE_AES_GCM_256)
#define USE_AES_GCM
#endif

//
//  Define which AES CCM algorithms are being used
//

#define USE_AES_CCM_16_64_128
#define USE_AES_CCM_16_64_256
#define USE_AES_CCM_64_64_128
#define USE_AES_CCM_64_64_256
#define USE_AES_CCM_16_128_128
#define USE_AES_CCM_16_128_256
#define USE_AES_CCM_64_128_128
#define USE_AES_CCM_64_128_256

#define INCLUDE_AES_CCM

//
//  Define which HMAC-SHA algorithms are being used
//

#define USE_HMAC_256_64
#define USE_HMAC_256_256
#define USE_HMAC_384_384
#define USE_HMAC_512_512
#if defined(USE_HMAC_256_64) || defined(USE_HMAC_256_256) || defined(USE_HMAC_384_384) || defined(USE_HMAC_512_512)
#define USE_HMAC
#endif

//
//  Define which AES CBC-MAC algorithms are to be used
//

#define USE_AES_CBC_MAC_128_64
#define USE_AES_CBC_MAC_128_128
#define USE_AES_CBC_MAC_256_64
#define USE_AES_CBC_MAC_256_128

//
//  Define which ECDH algorithms are to be used
//

#define USE_ECDH_ES_HKDF_256
#define USE_ECDH_ES_HKDF_512
#define USE_ECDH_SS_HKDF_256
#define USE_ECDH_SS_HKDF_512

#define USE_ECDH_ES_A128KW
#define USE_ECDH_ES_A192KW
#define USE_ECDH_ES_A256KW
#define USE_ECDH_SS_A128KW
#define USE_ECDH_SS_A192KW
#define USE_ECDH_SS_A256KW

//
//  Define which Key Wrap functions are to be used
//

#define USE_AES_KW_128
#define USE_AES_KW_192
#define USE_AES_KW_256

//
//  Define which of the DIRECT + KDF algorithms are to be used
//

#define USE_Direct_HKDF_HMAC_SHA_256
#define USE_Direct_HKDF_HMAC_SHA_512
#define USE_Direct_HKDF_AES_128
#define USE_Direct_HKDF_AES_256


//
//  Define which of the signature algorithms are to be used
//

#define USE_ECDSA_SHA_256
#define USE_ECDSA_SHA_384
#define USE_ECDSA_SHA_512


#define USE_OPEN_SSL 1
#define USE_BCRYPT 0

#define USE_COUNTER_SIGNATURES
