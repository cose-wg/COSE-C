#include "cose.h"
#include "configure.h"
#include "cose_int.h"
#include "crypto.h"

#include <assert.h>

#ifdef USE_OPEN_SSL

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>


bool AES_CCM_Decrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbKey, int cbKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	int NSize = 15 - LSize;
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

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, LSize, 0), COSE_ERR_DECRYPT_FAILED);
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
	int NSize = 15 - LSize;
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
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, LSize, 0), COSE_ERR_CRYPTO_FAIL);
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

	CHECK_CONDITION(cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Tag, cn_cbor_data_create(rgbOut, TSize/8, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);

	HMAC_cleanup(&ctx);
	return true;
}


void rand_bytes(byte * pb, size_t cb)
{
	RAND_bytes(pb, cb);
}

#endif // USE_OPEN_SSL
