#define USE_CBOR_CONTEXT 1

#include <cn-cbor\cn-cbor.h>
#include "configure.h"
typedef unsigned char byte;

typedef struct _cose * HCOSE;
typedef struct _cose_sign * HCOSE_SIGN;
typedef struct _cose_encrypt * HCOSE_ENCRYPT;
typedef struct _cose_recipient * HCOSE_RECIPIENT;


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
	COSE_ERR_DECRYPT_FAILED
} cose_error;

/**
* Errors
*/
typedef struct cose_errback {
	/** The error, or CN_CBOR_NO_ERROR if none */
	cose_error err;
} cose_errback;

//  Generic functions for the COSE library

HCOSE COSE_Decode(const byte * rgbData, int cbData, int * type, CBOR_CONTEXT_COMMA cose_errback * perr);  //  Decode the object
size_t COSE_Encode(HCOSE msg, byte * rgb, int ib, size_t cb);

cn_cbor * COSE_get_cbor(HCOSE hmsg);

//  Functions for the signing object

HCOSE_SIGN * COSE_Sign_Init(CBOR_CONTEXT_COMMA cose_errback * perr);
// COSE_SignMessage * COSE_Sign_Init(const cn_cbor * COMMA_CBOR_CONTEXT);


HCOSE_ENCRYPT  COSE_Encrypt_Init(CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Encrypt_Free(HCOSE_ENCRYPT cose);

typedef enum {
	COSE_PROTECT_ONLY = 1,
	COSE_UNPROTECT_ONLY = 2,
	COSE_BOTH = 3
} cose_protect_state;

typedef enum {
	COSE_Algorithm_AES_CCM_64 = 1,
	COSE_Algorithm_Direct,
	COSE_Algorithm_ECDH_ES_Direct
} COSE_Algorithms;

typedef enum {
	COSE_Header_Algorithm = 1,
	COSE_Header_KID,
	COSE_Header_Protected,
	COSE_Header_Unprotected,
	COSE_Header_IV,
	COSE_Header_Ciphertext,
	COSE_Header_Recipients,
	COSE_Header_Type
} COSE_Header;


void COSE_Encrypt_SetContent(HCOSE_ENCRYPT cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
void COSE_Encrypt_SetNonce(HCOSE_ENCRYPT cose, byte * rgbIV, size_t cbIV);

const cn_cbor * COSE_Encrypt_map_get_string(HCOSE_ENCRYPT cose, const char * key, int flags, cose_errback * errp);
const cn_cbor * COSE_Encrypt_map_get_int(HCOSE_ENCRYPT cose, int key, int flags, cose_errback * errp);

bool COSE_Encrypt_map_put(HCOSE_ENCRYPT cose, int key, cn_cbor * value, int flags, cose_errback * errp);

bool COSE_Encrypt_encrypt(HCOSE_ENCRYPT cose, cose_errback * perror);
bool COSE_Encrypt_decrypt(HCOSE_ENCRYPT, HCOSE_RECIPIENT, cose_errback * perr);

HCOSE_RECIPIENT COSE_Encrypt_add_shared_secret(HCOSE_ENCRYPT cose, COSE_Algorithms algId, byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, cose_errback * perr);

HCOSE_RECIPIENT COSE_Encrypt_GetRecipient(HCOSE_ENCRYPT cose, int iRecipient, cose_errback * perr);
bool COSE_Recipient_SetKey(HCOSE_RECIPIENT h, const byte * rgb, int cb, cose_errback * perr);
