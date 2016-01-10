#include "cose.h"
#include "configure.h"
#include "cose_int.h"
#include "crypto.h"

#include <assert.h>
#include <memory.h>

#ifdef USE_OPEN_SSL

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>


bool AES_CCM_Decrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, int cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
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

	CHECK_CONDITION(pIV->length == NSize, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbIV, pIV->v.str, pIV->length);

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
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
		break;
	}
	CHECK_CONDITION(EVP_DecryptInit_ex(&ctx, cipher, NULL, NULL, NULL), COSE_ERR_DECRYPT_FAILED);

	TSize /= 8; // Comes in in bits not bytes.
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, (LSize/8), 0), COSE_ERR_DECRYPT_FAILED);
	// CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize, 0), COSE_ERR_DECRYPT_FAILED);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, (void *) &pbCrypto[cbCrypto - TSize]), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptInit(&ctx, 0, pbKey, rgbIV), COSE_ERR_DECRYPT_FAILED);


	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, NULL, &cbOut, NULL, (int) cbCrypto - TSize), COSE_ERR_DECRYPT_FAILED);

	cbOut = (int)  cbCrypto - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, rgbOut, &cbOut, pbCrypto, (int) cbCrypto - TSize), COSE_ERR_DECRYPT_FAILED);

	EVP_CIPHER_CTX_cleanup(&ctx);

	pcose->pbContent = rgbOut;
	pcose->cbContent = cbOut;

	return true;
}


bool AES_CCM_Encrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	int NSize = 15 - (LSize/8);
	int outl = 0;
	const cn_cbor * cbor_iv = NULL;
	cn_cbor * cbor_iv_t = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif
	cn_cbor * cnTmp = NULL;
	const EVP_CIPHER * cipher;
	byte rgbIV[16];
	byte * pbIV = NULL;
	cn_cbor_errback cbor_error;

	switch (cbKey*8) {
	case 128:
		cipher = EVP_aes_128_ccm();
		break;

	case 192:
		cipher = EVP_aes_192_ccm();
		break;

	case 256:
		cipher = EVP_aes_256_ccm();
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
		
		//  Setup the IV/Nonce and put it into the message
	cbor_iv = _COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, perr);
	if (cbor_iv == NULL) {
		pbIV = COSE_CALLOC(NSize, 1, context);
		CHECK_CONDITION(pbIV != NULL, COSE_ERR_OUT_OF_MEMORY);
		rand_bytes(pbIV, NSize);
		memcpy(rgbIV, pbIV, NSize);
		cbor_iv_t = cn_cbor_data_create(pbIV, NSize, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(cbor_iv_t != NULL, cbor_error);
		pbIV = NULL;

		if (!_COSE_map_put(&pcose->m_message, COSE_Header_IV, cbor_iv_t, COSE_UNPROTECT_ONLY, perr)) goto errorReturn;
		cbor_iv_t = NULL;
	}
	else {
		CHECK_CONDITION(cbor_iv->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(cbor_iv->length == NSize, COSE_ERR_INVALID_PARAMETER);
		memcpy(rgbIV, cbor_iv->v.str, cbor_iv->length);
	}

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	CHECK_CONDITION(EVP_EncryptInit_ex(&ctx, cipher, NULL, NULL, NULL), COSE_ERR_CRYPTO_FAIL);

	TSize /= 8; // Comes in in bits not bytes.
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, (LSize/8), 0), COSE_ERR_CRYPTO_FAIL);
	// CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize, 0), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, NULL), COSE_ERR_CRYPTO_FAIL);	// Say we are doing an 8 byte tag

	CHECK_CONDITION(EVP_EncryptInit(&ctx, 0, pbKey, rgbIV), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, 0, &cbOut, 0, (int) pcose->cbContent), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);

	rgbOut = (byte *)COSE_CALLOC(cbOut+TSize, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pcose->pbContent, (int) pcose->cbContent), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptFinal_ex(&ctx, &rgbOut[cbOut], &cbOut), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, TSize, &rgbOut[pcose->cbContent]), COSE_ERR_CRYPTO_FAIL);

	cnTmp = cn_cbor_data_create(rgbOut, (int)pcose->cbContent + TSize, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(cnTmp != NULL, COSE_ERR_CBOR);
	rgbOut = NULL;

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
	cnTmp = NULL;

	EVP_CIPHER_CTX_cleanup(&ctx);
	return true;

errorReturn:
	if (pbIV != NULL) COSE_FREE(pbIV, context);
	if (cbor_iv_t != NULL) COSE_FREE(cbor_iv_t, context);
	if (rgbOut != NULL) COSE_FREE(rgbOut, context);
	if (cnTmp != NULL) COSE_FREE(cnTmp, context);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return false;
}

bool AES_GCM_Decrypt(COSE_Enveloped * pcose, const byte * pbKey, int cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	int outl = 0;
	byte rgbIV[15] = { 0 };
	const cn_cbor * pIV = NULL;
	const EVP_CIPHER * cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif
	int TSize = 128 / 8;

	assert(perr != NULL);
	EVP_CIPHER_CTX_init(&ctx);

	//  Setup the IV/Nonce and put it into the message

	pIV = _COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, NULL);
	if ((pIV == NULL) || (pIV->type != CN_CBOR_BYTES)) {
		perr->err = COSE_ERR_INVALID_PARAMETER;

	errorReturn:
		if (rgbOut != NULL) COSE_FREE(rgbOut, context);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return false;
	}

	CHECK_CONDITION(pIV->length == 96/8, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbIV, pIV->v.str, pIV->length);

	//  Setup and run the OpenSSL code

	switch (cbKey) {
	case 128 / 8:
		cipher = EVP_aes_128_gcm();
		break;

	case 192 / 8:
		cipher = EVP_aes_192_gcm();
		break;

	case 256 / 8:
		cipher = EVP_aes_256_gcm();
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
		break;
	}

	//  Do the setup for OpenSSL

	CHECK_CONDITION(EVP_DecryptInit_ex(&ctx, cipher, NULL, NULL, NULL), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, (void *)&pbCrypto[cbCrypto - TSize]), COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptInit(&ctx, 0, pbKey, rgbIV), COSE_ERR_DECRYPT_FAILED);
	
	//  Pus in the AAD

	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData), COSE_ERR_DECRYPT_FAILED);

	//  

	cbOut = (int)cbCrypto - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	//  Process content

	CHECK_CONDITION(EVP_DecryptUpdate(&ctx, rgbOut, &cbOut, pbCrypto, (int)cbCrypto - TSize), COSE_ERR_DECRYPT_FAILED);

	//  Process Tag

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, TSize, (byte *)pbCrypto + cbCrypto - TSize), COSE_ERR_DECRYPT_FAILED);

	//  Check the result

	CHECK_CONDITION(EVP_DecryptFinal(&ctx, rgbOut + cbOut, &cbOut), COSE_ERR_DECRYPT_FAILED);

	EVP_CIPHER_CTX_cleanup(&ctx);

	pcose->pbContent = rgbOut;
	pcose->cbContent = cbOut;

	return true;
}

bool AES_GCM_Encrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	int outl = 0;
	byte rgbIV[16] = { 0 };
	byte * pbIV = NULL;
	const cn_cbor * cbor_iv = NULL;
	cn_cbor * cbor_iv_t = NULL;
	const EVP_CIPHER * cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif
	cn_cbor_errback cbor_error;

	//  Setup the IV/Nonce and put it into the message

	cbor_iv = _COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, perr);
	if (cbor_iv == NULL) {
		pbIV = COSE_CALLOC(96, 1, context);
		CHECK_CONDITION(pbIV != NULL, COSE_ERR_OUT_OF_MEMORY);
		rand_bytes(pbIV, 96 / 8);
		memcpy(rgbIV, pbIV, 96 / 8);
		cbor_iv_t = cn_cbor_data_create(pbIV, 96 / 8, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(cbor_iv_t != NULL, cbor_error);
		pbIV = NULL;

		if (!_COSE_map_put(&pcose->m_message, COSE_Header_IV, cbor_iv_t, COSE_UNPROTECT_ONLY, perr)) goto errorReturn;
		cbor_iv_t = NULL;
	}
	else {
		CHECK_CONDITION(cbor_iv->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(cbor_iv->length == 96 / 8, COSE_ERR_INVALID_PARAMETER);
		memcpy(rgbIV, cbor_iv->v.str, cbor_iv->length);
	}


	switch (cbKey*8) {
	case 128:
		cipher = EVP_aes_128_gcm();
		break;

	case 192:
		cipher = EVP_aes_192_gcm();
		break;

	case 256:
		cipher = EVP_aes_256_gcm();
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
		break;
	}

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	CHECK_CONDITION(EVP_EncryptInit_ex(&ctx, cipher, NULL, NULL, NULL), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptInit(&ctx, 0, pbKey, rgbIV), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);

	rgbOut = (byte *)COSE_CALLOC(pcose->cbContent + 128/8, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pcose->pbContent, (int)pcose->cbContent), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptFinal_ex(&ctx, &rgbOut[cbOut], &cbOut), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, 128/8, &rgbOut[pcose->cbContent]), COSE_ERR_CRYPTO_FAIL);

	cn_cbor * cnTmp = cn_cbor_data_create(rgbOut, (int)pcose->cbContent + 128/8, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(cnTmp != NULL, COSE_ERR_CBOR);
	rgbOut = NULL;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return true;

errorReturn:
	if (pbIV != NULL) COSE_FREE(pbIV, context);
	if (cbor_iv_t != NULL) COSE_FREE(cbor_iv_t, context);
	if (rgbOut != NULL) COSE_FREE(rgbOut, context);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return false;
}


bool AES_CBC_MAC_Create(COSE_MacMessage * pcose, int KeySize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	const EVP_CIPHER * pcipher = NULL;
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte rgbIV[16] = { 0 };
	byte * rgbOut = NULL;
	bool f = false;
	unsigned int i;
	cn_cbor * cn = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	rgbOut = COSE_CALLOC(16, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	switch (KeySize) {
	case 128:
		pcipher = EVP_aes_128_cbc();
		break;

	case 256:
		pcipher = EVP_aes_256_cbc();
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	CHECK_CONDITION(EVP_EncryptInit_ex(&ctx, pcipher, NULL, pcose->pbKey, rgbIV), COSE_ERR_CRYPTO_FAIL);

	for (i = 0; i < (unsigned int)cbAuthData / 16; i++) {
		CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pbAuthData + (i * 16), 16), COSE_ERR_CRYPTO_FAIL);
	}
	if (cbAuthData % 16 != 0) {
		CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pbAuthData + (i * 16), cbAuthData % 16), COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, rgbIV, 16 - (cbAuthData % 16)), COSE_ERR_CRYPTO_FAIL);
	}

	cn = cn_cbor_data_create(rgbOut, TSize / 8, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(cn != NULL, COSE_ERR_OUT_OF_MEMORY);
	rgbOut = NULL;

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cn, INDEX_MAC_TAG, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
	cn = NULL;

	EVP_CIPHER_CTX_cleanup(&ctx);
	return !f;

errorReturn:
	if (rgbOut != NULL) COSE_FREE(rgbOut, context);
	if (cn != NULL) CN_CBOR_FREE(cn, context);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return false;
}

bool AES_CBC_MAC_Validate(COSE_MacMessage * pcose, int TSize, const byte * pbKey, int cbitKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	const EVP_CIPHER * pcipher = NULL;
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte rgbIV[16] = { 0 };
	byte rgbTag[16] = { 0 };
	bool f = false;
	unsigned int i;

	switch (cbitKey) {
	case 128:
		pcipher = EVP_aes_128_cbc();
		break;

	case 256:
		pcipher = EVP_aes_256_cbc();
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	CHECK_CONDITION(EVP_EncryptInit_ex(&ctx, pcipher, NULL, pbKey, rgbIV), COSE_ERR_CRYPTO_FAIL);

	TSize /= 8;

	for (i = 0; i < (unsigned int) cbAuthData / 16; i++) {
		CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbTag, &cbOut, pbAuthData+(i*16), 16), COSE_ERR_CRYPTO_FAIL);
	}
	if (cbAuthData % 16 != 0) {
		CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbTag, &cbOut, pbAuthData + (i * 16), cbAuthData % 16), COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(EVP_EncryptUpdate(&ctx, rgbTag, &cbOut, rgbIV, 16 - (cbAuthData % 16)), COSE_ERR_CRYPTO_FAIL);
	}

	cn_cbor * cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != NULL, COSE_ERR_CBOR);

	for (i = 0; i < (unsigned int)TSize; i++) f |= (cn->v.bytes[i] != rgbTag[i]);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return !f;

errorReturn:
	EVP_CIPHER_CTX_cleanup(&ctx);
	return false;
}

#if 0
//  We are doing CBC-MAC not CMAC at this time
bool AES_CMAC_Validate(COSE_MacMessage * pcose, int KeySize, int TagSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	CMAC_CTX * pctx = NULL;
	const EVP_CIPHER * pcipher = NULL;
	byte * rgbOut = NULL;
	size_t cbOut;
	bool f = false;
	unsigned int i;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	pctx = CMAC_CTX_new();


	switch (KeySize) {
	case 128: pcipher = EVP_aes_128_cbc(); break;
	case 256: pcipher = EVP_aes_256_cbc(); break;
	default: FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER); break;
	}

	rgbOut = COSE_CALLOC(128/8, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(CMAC_Init(pctx, pcose->pbKey, pcose->cbKey, pcipher, NULL /*impl*/) == 1, COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(CMAC_Update(pctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(CMAC_Final(pctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

	cn_cbor * cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != NULL, COSE_ERR_CBOR);

	for (i = 0; i < (unsigned int)TagSize / 8; i++) f |= (cn->v.bytes[i] != rgbOut[i]);

	COSE_FREE(rgbOut, context);
	CMAC_CTX_cleanup(pctx);
	CMAC_CTX_free(pctx);
	return !f;

errorReturn:
	COSE_FREE(rgbOut, context);
	CMAC_CTX_cleanup(pctx);
	CMAC_CTX_free(pctx);
	return false;

}
#endif

bool HMAC_Create(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	HMAC_CTX ctx;
	const EVP_MD * pmd = NULL;
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
	case 384: pmd = EVP_sha384(); break;
	case 512: pmd = EVP_sha512(); break;
	default: FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER); break;
	}

	rgbOut = COSE_CALLOC(EVP_MAX_MD_SIZE, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(HMAC_Init(&ctx, pcose->pbKey, (int) pcose->cbKey, pmd), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Update(&ctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Final(&ctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cn_cbor_data_create(rgbOut, TSize / 8, CBOR_CONTEXT_PARAM_COMMA NULL), INDEX_MAC_TAG, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);

	HMAC_cleanup(&ctx);
	return true;
}

bool HMAC_Validate(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, int cbitKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	HMAC_CTX ctx;
	const EVP_MD * pmd = NULL;
	byte * rgbOut = NULL;
	unsigned int cbOut;
	bool f = false;
	unsigned int i;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	HMAC_CTX_init(&ctx);

	switch (HSize) {
	case 256: pmd = EVP_sha256(); break;
	case 384: pmd = EVP_sha384(); break;
	case 512: pmd = EVP_sha512(); break;
	default: FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER); break;
	}

	rgbOut = COSE_CALLOC(EVP_MAX_MD_SIZE, 1, context);
	CHECK_CONDITION(rgbOut != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(HMAC_Init(&ctx, pbKey, cbitKey/8, pmd), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Update(&ctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Final(&ctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

	cn_cbor * cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != NULL, COSE_ERR_CBOR);

	if (cn->length > (int) cbOut) return false;
	for (i = 0; i < (unsigned int) TSize/8; i++) f |= (cn->v.bytes[i] != rgbOut[i]);

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

EC_KEY * ECKey_From(const cn_cbor * pKey, int * cbGroup, cose_errback * perr)
{
	EC_KEY * pNewKey = EC_KEY_new();
	byte  rgbKey[512+1];
	const cn_cbor * p;
	int nidGroup = -1;
	EC_POINT * pPoint = NULL;

	p = cn_cbor_mapget_int(pKey, COSE_Key_EC_Curve);
	CHECK_CONDITION(p != NULL, COSE_ERR_INVALID_PARAMETER);

	switch (p->v.sint) {
	case 1: // P-256
		nidGroup = NID_X9_62_prime256v1;
		*cbGroup = 256 / 8;
		break;

	case 2: // P-384
		nidGroup = NID_secp384r1;
		*cbGroup = 384 / 8;
		break;

	case 3: // P-521
		nidGroup = NID_secp521r1;
		*cbGroup = (521 + 7) / 8;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
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

		pbn = BN_bin2bn(p->v.bytes, (int) p->length, NULL);
		EC_KEY_set_private_key(pNewKey, pbn);
	}
	
	return pNewKey;

 errorReturn:
	return NULL;
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

bool ECDSA_Sign(COSE_SignerInfo * pSigner, int cbitDigest, const byte * rgbToSign, size_t cbToSign, cose_errback * perr)
{
	EC_KEY * eckey = NULL;
	byte rgbDigest[EVP_MAX_MD_SIZE];
	unsigned int cbDigest = sizeof(rgbDigest);
	byte  * pbSig = NULL;
	const EVP_MD * digest;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * p = NULL;
	ECDSA_SIG * psig = NULL;
	cn_cbor_errback cbor_error;
	int cbR;
	byte rgbSig[66];
	int cb;
	
	eckey = ECKey_From(pSigner->m_pkey, &cbR, perr);
	if (eckey == NULL) {
	errorReturn:
		if (p != NULL) CN_CBOR_FREE(p, context);
		if (eckey != NULL) EC_KEY_free(eckey);
		return false;
	}

	switch (cbitDigest) {
	case 256: digest = EVP_sha256(); break;
	case 512: digest = EVP_sha512(); break;
	case 384: digest = EVP_sha384(); break;
	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	EVP_Digest(rgbToSign, cbToSign, rgbDigest, &cbDigest, digest, NULL);

	psig = ECDSA_do_sign(rgbDigest, cbDigest, eckey);
	CHECK_CONDITION(psig != NULL, COSE_ERR_CRYPTO_FAIL);

	pbSig = COSE_CALLOC(cbR, 2, context);
	CHECK_CONDITION(pbSig != NULL, COSE_ERR_OUT_OF_MEMORY);



	cb = BN_bn2bin(psig->r, rgbSig);
	CHECK_CONDITION(cb <= cbR, COSE_ERR_INVALID_PARAMETER);
	memcpy(pbSig + cbR - cb, rgbSig, cb);

	cb = BN_bn2bin(psig->s, rgbSig);
	CHECK_CONDITION(cb <= cbR, COSE_ERR_INVALID_PARAMETER);
	memcpy(pbSig + 2*cbR - cb, rgbSig, cb);

	p = cn_cbor_data_create(pbSig, cbR*2, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(p != NULL, cbor_error);

	CHECK_CONDITION(_COSE_array_replace(&pSigner->m_message, p, INDEX_SIGNATURE, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
	
	return true;
}

bool ECDSA_Verify(COSE_SignerInfo * pSigner, int cbitDigest, const byte * rgbToSign, size_t cbToSign, const byte * rgbSignature, size_t cbSignature, cose_errback * perr)
{
	EC_KEY * eckey = NULL;
	byte rgbDigest[EVP_MAX_MD_SIZE];
	unsigned int cbDigest = sizeof(rgbDigest);
	const EVP_MD * digest;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * p = NULL;
	ECDSA_SIG sig = { NULL, NULL };
	int cbR;

	eckey = ECKey_From(pSigner->m_pkey, &cbR, perr);
	if (eckey == NULL) {
	errorReturn:
		if (sig.r != NULL) BN_free(sig.r);
		if (sig.s != NULL) BN_free(sig.s);
		if (p != NULL) CN_CBOR_FREE(p, context);
		if (eckey != NULL) EC_KEY_free(eckey);
		return false;
	}

	switch (cbitDigest) {
	case 256: digest = EVP_sha256(); break;
	case 512: digest = EVP_sha512(); break;
	case 384: digest = EVP_sha384(); break;
	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
	EVP_Digest(rgbToSign, cbToSign, rgbDigest, &cbDigest, digest, NULL);

	CHECK_CONDITION(cbSignature / 2 == cbR, COSE_ERR_INVALID_PARAMETER);
	sig.r = BN_bin2bn(rgbSignature,(int) cbSignature/2, NULL);
	sig.s = BN_bin2bn(rgbSignature+cbSignature/2, (int) cbSignature/2, NULL);

	CHECK_CONDITION(ECDSA_do_verify(rgbDigest, cbDigest, &sig, eckey) == 1, COSE_ERR_CRYPTO_FAIL);

	BN_free(sig.r);
	BN_free(sig.s);

	return true;
}

bool AES_KW_Decrypt(COSE_Enveloped * pcose, const byte * pbKeyIn, size_t cbitKey, const byte * pbCipherText, size_t cbCipherText, byte * pbKeyOut, int * pcbKeyOut, cose_errback * perr)
{
	byte rgbOut[256 / 8];
	AES_KEY key;

	CHECK_CONDITION(AES_set_decrypt_key(pbKeyIn, (int)cbitKey, &key) == 0, COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(AES_unwrap_key(&key, NULL, rgbOut, pbCipherText, (int) cbCipherText), COSE_ERR_CRYPTO_FAIL);

	memcpy(pbKeyOut, rgbOut, cbCipherText - 8);
	*pcbKeyOut = (int) (cbCipherText - 8);

	return true;
errorReturn:
	return false;
}

bool AES_KW_Encrypt(COSE_RecipientInfo * pcose, const byte * pbKeyIn, int cbitKey, const byte *  pbContent, int  cbContent, cose_errback * perr)
{
	byte  *pbOut = NULL;
	AES_KEY key;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_encrypt.m_message.m_allocContext;
#endif
	cn_cbor * cnTmp = NULL;

	pbOut = COSE_CALLOC(cbContent + 8, 1, context);

	CHECK_CONDITION(AES_set_encrypt_key(pbKeyIn, cbitKey, &key) == 0, COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(AES_wrap_key(&key, NULL, pbOut, pbContent, cbContent), COSE_ERR_CRYPTO_FAIL);

	cnTmp = cn_cbor_data_create(pbOut, (int)cbContent + 8, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(cnTmp != NULL, COSE_ERR_CBOR);
	pbOut = NULL;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_encrypt.m_message, cnTmp, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
	cnTmp = NULL;

	return true;

errorReturn:
	COSE_FREE(cnTmp, context);
	if (pbOut != NULL) COSE_FREE(pbOut, context);
	return false;
}


void rand_bytes(byte * pb, size_t cb)
{
	RAND_bytes(pb, (int) cb);
}

#endif // USE_OPEN_SSL
