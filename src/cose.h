#include <cn-cbor/cn-cbor.h>
#include "configure.h"
typedef unsigned char byte;

typedef struct _cose * HCOSE;
typedef struct _cose_sign * HCOSE_SIGN;
typedef struct _cose_signer * HCOSE_SIGNER;
typedef struct _cose_encrypt * HCOSE_ENCRYPT;
typedef struct _cose_recipient * HCOSE_RECIPIENT;
typedef struct _cose_mac * HCOSE_MAC;

/**
* All of the different kinds of errors
*/
typedef enum cose_error {
	/** No error has occurred */
	COSE_ERR_NONE,
	/** An invalid parameter was passed to a function */
	COSE_ERR_INVALID_PARAMETER,
	/** Allocation failed */
	COSE_ERR_OUT_OF_MEMORY,
	/** Error in processing CBOR */
	COSE_ERR_CBOR,
	/** Unknown algorithm found */
	COSE_ERR_UNKNOWN_ALGORITHM,
	/** No usable recipient found */
	COSE_ERR_NO_RECIPIENT_FOUND,
	/** Decryption operation failed */
	COSE_ERR_DECRYPT_FAILED,
	/** Cryptographic failure */
	COSE_ERR_CRYPTO_FAIL
} cose_error;

/**
* Errors
*/
typedef struct _cose_errback {
	/** The error, or CN_CBOR_NO_ERROR if none */
	cose_error err;
} cose_errback;

//  Generic functions for the COSE library

HCOSE COSE_Decode(const byte * rgbData, int cbData, int * type, CBOR_CONTEXT_COMMA cose_errback * perr);  //  Decode the object
size_t COSE_Encode(HCOSE msg, byte * rgb, int ib, size_t cb);

cn_cbor * COSE_get_cbor(HCOSE hmsg);

//  Functions for the signing object

HCOSE_SIGN COSE_Sign_Init(CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Sign_Free(HCOSE_SIGN cose);

HCOSE_ENCRYPT  COSE_Encrypt_Init(CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Encrypt_Free(HCOSE_ENCRYPT cose);

HCOSE_MAC COSE_Mac_Init(CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Mac_Free(HCOSE_MAC cose);

typedef enum {
	COSE_PROTECT_ONLY = 1,
	COSE_UNPROTECT_ONLY = 2,
	COSE_DONT_SEND = 4,
	COSE_BOTH = 7
} cose_protect_state;

typedef enum {
	COSE_Algorithm_HMAC_256_256 = 4,

	COSE_Algorithm_AES_CCM_16_64_128 = 10,
	COSE_Algorithm_AES_CCM_16_64_256 = 11,
	COSE_Algorithm_AES_CCM_64_64_128 = 30,
	COSE_Algorithm_AES_CCM_64_64_256 = 31,
	COSE_Algorithm_AES_CCM_16_128_128 = 12,
	COSE_Algorithm_AES_CCM_16_128_256 = 13,
	COSE_Algorithm_AES_CCM_64_128_128 = 32,
	COSE_Algorithm_AES_CCM_64_128_256 = 33,

	COSE_Algorithm_Direct = -6,
	COSE_Algorithm_ECDH_ES_Direct, 
	COSE_Algorithm_PS256 = -26,
	COSE_Algorithm_PS384 = -27,
	COSE_Algorithm_PS512 = -28,
	COSE_Algorithm_ECDSA_SHA_256 = -7,
} COSE_Algorithms;

typedef enum {
	COSE_Header_Algorithm = 1,
	COSE_Header_KID,
	COSE_Header_IV,
} COSE_Header;

typedef enum {
	COSE_Key_Type_EC2 = 2,
	COSE_Key_Type = 1,
	COSE_Key_ID = 2,
	COSE_Parameter_KID = 4,
} COSE_Constants;

bool COSE_Encrypt_SetContent(HCOSE_ENCRYPT cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
bool COSE_Encrypt_SetNonce(HCOSE_ENCRYPT cose, byte * rgbIV, size_t cbIV);

cn_cbor * COSE_Encrypt_map_get_string(HCOSE_ENCRYPT cose, const char * key, int flags, cose_errback * errp);
cn_cbor * COSE_Encrypt_map_get_int(HCOSE_ENCRYPT cose, int key, int flags, cose_errback * errp);

bool COSE_Encrypt_map_put(HCOSE_ENCRYPT cose, int key, cn_cbor * value, int flags, cose_errback * errp);

bool COSE_Encrypt_encrypt(HCOSE_ENCRYPT cose, cose_errback * perror);
bool COSE_Encrypt_decrypt(HCOSE_ENCRYPT, HCOSE_RECIPIENT, cose_errback * perr);

HCOSE_RECIPIENT COSE_Encrypt_add_shared_secret(HCOSE_ENCRYPT cose, COSE_Algorithms algId, byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, cose_errback * perr);

HCOSE_RECIPIENT COSE_Encrypt_GetRecipient(HCOSE_ENCRYPT cose, int iRecipient, cose_errback * perr);
bool COSE_Recipient_SetKey(HCOSE_RECIPIENT h, const byte * rgb, int cb, cose_errback * perr);

//
//

bool COSE_Mac_SetContent(HCOSE_MAC cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);

cn_cbor * COSE_Mac_map_get_int(HCOSE_MAC h, int key, int flags, cose_errback * perror);
bool COSE_Mac_map_put(HCOSE_MAC cose, int key, cn_cbor * value, int flags, cose_errback * errp);

bool COSE_Mac_encrypt(HCOSE_MAC cose, cose_errback * perror);
bool COSE_Mac_validate(HCOSE_MAC, HCOSE_RECIPIENT, cose_errback * perr);

bool COSE_Encrypt_SetContent(HCOSE_ENCRYPT cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);

HCOSE_RECIPIENT COSE_Mac_add_shared_secret(HCOSE_MAC cose, COSE_Algorithms algId, byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, cose_errback * perr);

HCOSE_RECIPIENT COSE_Mac_GetRecipient(HCOSE_MAC cose, int iRecipient, cose_errback * perr);

//
//

bool COSE_Sign_SetContent(HCOSE_SIGN cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
HCOSE_SIGNER COSE_Sign_add_signer(HCOSE_SIGN cose, const cn_cbor * pkey, int algId, cose_errback * perr);
bool COSE_Sign_Sign(HCOSE_SIGN h, cose_errback * perr);
