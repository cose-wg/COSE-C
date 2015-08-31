#include "cose.h"
#include "configure.h"
#include "cose_int.h"
#include "crypto.h"

#include <assert.h>

#ifdef USE_OPEN_SSL

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>


bool AES_CCM_Decrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbKey, int cbKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	int NSize = 15 - (LSize/8);
	int outl = 0;
	byte rgbIV[15] = { 0 };
	const cn_cbor * pIV = NULL;
	const EVP_CIPHER * cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	assert(perr != NULL);
	EVP_CIPHER_CTX_init(&ctx);

	//  Setup the IV/Nonce and put it into the message

	pIV = _COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, NULL);
	if ((pIV == NULL) || (pIV->type!= CN_CBOR_BYTES)) {
		perr->err = COSE_ERR_INVALID_PARAMETER;

	errorReturn:
		if (rgbOut != NULL) COSE_FREE(rgbOut, context);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return false;
	}

	CHECK_CONDITION(pIV->length <= NSize, COSE_ERR_INVALID_PARAMETER);
	memcpy(&rgbIV[NSize - pIV->length], pIV->v.str, pIV->length);

	//  Setup and run the OpenSSL code

	switch (cbKey) {
	case 128/8:
		cipher = EVP_aes_128_ccm();
		break;

	case 192/8:
		cipher = EVP_aes_192_ccm();
		break;

	case 256/8:
		cipher = EVP_aes_256_ccm();
		break;

	default:
		CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
		break;
	}
	CHECK_CONDITION(EVP_DecryptInit_ex(&ctx, cipher, NULL, NULL, NULL), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, (LSize/8), 0), COSE_ERR_DECRYPT_FAILED);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize, 0), COSE_ERR_DECRYPT_FAILED);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, &pcose->pbContent[pcose->cbContent - TSize]), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptInit(&ctx, 0, pbKey, rgbIV), COSE_ERR_DECRYPT_FAILED);


	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, NULL, &cbOut, NULL, pcose->cbContent-TSize), COSE_ERR_DECRYPT_FAILED);

	cbOut = pcose->cbContent - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != NULL, CN_CBOR_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, rgbOut, &cbOut, pcose->pbContent, pcose->cbContent-TSize), COSE_ERR_DECRYPT_FAILED);

	EVP_CIPHER_CTX_cleanup(&ctx);

	pcose->pbContent = rgbOut;
	pcose->cbContent = cbOut;

	return true;
}


bool AES_CCM_Encrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	int NSize = 15 - (LSize/8);
	int outl = 0;
	byte rgbIV[15] = { 0 };
	const cn_cbor * cbor_iv = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	//  Setup the IV/Nonce and put it into the message

	cbor_iv = _COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, NULL);
	if ((cbor_iv == NULL) || (cbor_iv->type != CN_CBOR_BYTES)) {
		perr->err = COSE_ERR_INVALID_PARAMETER;
		errorReturn:
		if (rgbOut != NULL) COSE_FREE(rgbOut, context);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return false;
	}

	CHECK_CONDITION(cbor_iv->length <= NSize, COSE_ERR_INVALID_PARAMETER);
	memcpy(&rgbIV[NSize-cbor_iv->length], cbor_iv->v.str, cbor_iv->length);

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	CHECK_CONDITION(EVP_EncryptInit_ex(&ctx, EVP_aes_128_ccm(), NULL, NULL, NULL), COSE_ERR_CRYPTO_FAIL);

	TSize /= 8; // Comes in in bits not bytes.
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, (LSize/8), 0), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize, 0), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, NULL), COSE_ERR_CRYPTO_FAIL);	// Say we are doing an 8 byte tag

	CHECK_CONDITION(EVP_EncryptInit(&ctx, 0, pcose->pbKey, rgbIV), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, 0, &cbOut, 0, pcose->cbContent), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);

	rgbOut = (byte *)COSE_CALLOC(cbOut + TSize, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pcose->pbContent, pcose->cbContent), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptFinal_ex(&ctx, &rgbOut[cbOut], &cbOut), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, TSize, &rgbOut[pcose->cbContent]), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Ciphertext, cn_cbor_data_create(rgbOut,  pcose->cbContent + TSize, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return true;
}

bool HMAC_Create(COSE_Encrypt * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	HMAC_CTX ctx;
	EVP_MD * pmd = NULL;
	byte * rgbOut = NULL;
	unsigned int cbOut;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	HMAC_CTX_init(&ctx);

	if (0) {
	errorReturn:
		COSE_FREE(rgbOut, context);
		HMAC_cleanup(&ctx);
		return false;
	}

	switch (HSize) {
	case 256: pmd = EVP_sha256(); break;
	default: CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER); break;
	}

	rgbOut = COSE_CALLOC(EVP_MAX_MD_SIZE, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(HMAC_Init(&ctx, pcose->pbKey, pcose->cbKey, pmd), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Update(&ctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Final(&ctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

#ifdef USE_ARRAY
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cn_cbor_data_create(rgbOut, TSize / 8, CBOR_CONTEXT_PARAM_COMMA NULL), INDEX_MAC_TAG, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
#else
	CHECK_CONDITION(cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Tag, cn_cbor_data_create(rgbOut, TSize/8, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
#endif

	HMAC_cleanup(&ctx);
	return true;
}

bool HMAC_Validate(COSE_Encrypt * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	HMAC_CTX ctx;
	EVP_MD * pmd = NULL;
	byte * rgbOut = NULL;
	unsigned int cbOut;
	bool f = false;
	int i;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	HMAC_CTX_init(&ctx);


	switch (HSize) {
	case 256: pmd = EVP_sha256(); break;
	default: CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER); break;
	}

	rgbOut = COSE_CALLOC(EVP_MAX_MD_SIZE, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(HMAC_Init(&ctx, pcose->pbKey, pcose->cbKey, pmd), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Update(&ctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Final(&ctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

#ifdef USE_ARRAY
	cn_cbor * cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != NULL, COSE_ERR_CBOR);
#else
#endif

	if (cn->length != cbOut) return false;
	for (i = 0; i < cbOut; i++) f |= (cn->v.str[i] != rgbOut[i]);

	HMAC_cleanup(&ctx);
	return !f;

errorReturn:
	COSE_FREE(rgbOut, context);
	HMAC_cleanup(&ctx);
	return false;

}

#define COSE_Key_EC_Curve -1
#define COSE_Key_EC_X -2
#define COSE_Key_EC_Y -3
#define COSE_Key_EC_d -4

EC_KEY * ECKey_From(const cn_cbor * pKey, cose_errback * perr)
{
	EC_KEY * pNewKey = EC_KEY_new();
	byte  rgbKey[512+1];
	const cn_cbor * p;
	int nidGroup = -1;
	EC_POINT * pPoint = NULL;

	p = cn_cbor_mapget_int(pKey, COSE_Key_EC_Curve);
	if (p == NULL) return NULL;
	switch (p->v.sint) {
	case 1: // P-256
		nidGroup = NID_X9_62_prime256v1;
		break;

	case 2: // P-384
		nidGroup = NID_secp384r1;
		break;

	case 3: // P-521
		nidGroup = NID_secp521r1;
		break;

	default:
		return NULL;
	}

	EC_GROUP * ecgroup = EC_GROUP_new_by_curve_name(nidGroup);
	EC_KEY_set_group(pNewKey, ecgroup);

	rgbKey[0] = POINT_CONVERSION_UNCOMPRESSED;
	p = cn_cbor_mapget_int(pKey, COSE_Key_EC_X);
	if (p == NULL) return NULL;
	if (p->type != CN_CBOR_BYTES) return NULL;
	memcpy(rgbKey+1, p->v.str, p->length);

	p = cn_cbor_mapget_int(pKey, COSE_Key_EC_Y);
	if (p == NULL) return NULL;
	if (p->type != CN_CBOR_BYTES) return NULL;
	memcpy(rgbKey + p->length+1, p->v.str, p->length);

	pPoint = EC_POINT_new(ecgroup);
	EC_POINT_oct2point(ecgroup, pPoint, rgbKey, p->length * 2 + 1, NULL);
	EC_KEY_set_public_key(pNewKey, pPoint);

	p = cn_cbor_mapget_int(pKey, COSE_Key_EC_d);
	if (p != NULL) {
		BIGNUM * pbn;

		pbn = BN_bin2bn(p->v.str, p->length, NULL);
		EC_KEY_set_private_key(pNewKey, pbn);
	}
	
	return pNewKey;
}

/*
bool ECDSA_Sign(const cn_cbor * pKey)
{
	byte * digest = NULL;
	int digestLen = 0;
	ECDSA_SIG * sig;

	EC_KEY * eckey = ECKey_From(pKey);

	sig = ECDSA_do_sign(digest, digestLen, eckey);

	return true;
}
*/

bool ECDSA_Sign(COSE_SignerInfo * pSigner, const byte * rgbToSign, size_t cbToSign, cose_errback * perr)
{
	EC_KEY * eckey = NULL;
	byte rgbDigest[EVP_MAX_MD_SIZE];
	size_t cbDigest = sizeof(rgbDigest);
	ECDSA_SIG * sig;
	byte  * pbSig = NULL;
	size_t cbSig;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * p = NULL;
	
	eckey = ECKey_From(pSigner->m_pkey, perr);
	if (eckey == NULL) {
	errorReturn:
		if (p != NULL) CN_CBOR_FREE(p, context);
		if (eckey != NULL) EC_KEY_free(eckey);
		return false;
	}

	EVP_Digest(rgbToSign, cbToSign, rgbDigest, &cbDigest, EVP_sha256(), NULL);

	cbSig = ECDSA_size(eckey);
	pbSig = COSE_CALLOC(cbSig, 1, context);
	CHECK_CONDITION(pbSig != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(ECDSA_sign(0, rgbDigest, cbDigest, pbSig, &cbSig, eckey), COSE_ERR_CRYPTO_FAIL);

	p = cn_cbor_data_create(pbSig, cbSig, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(p != NULL, COSE_ERR_OUT_OF_MEMORY);

#ifdef USE_ARRAY
	CHECK_CONDITION(_COSE_array_replace(&pSigner->m_message, p, INDEX_SIGNATURE, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
#else
	CHECK_CONDITION(cn_cbor_mapput_int(pSigner->m_message.m_cbor, COSE_Header_Signature, p, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
#endif
	
	return true;
}


void rand_bytes(byte * pb, size_t cb)
{
	RAND_bytes(pb, cb);
}

#endif // USE_OPEN_SSL
