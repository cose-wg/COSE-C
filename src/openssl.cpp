#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "cose_crypto.h"

#include <assert.h>
#ifdef __MBED__
#include <string.h>
#else
#include <memory.h>
#endif
#include <stdbool.h>

#ifdef COSE_C_USE_OPENSSL

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

/*******************************************/

#define Safe_OPENSSL(handleName, freeFunction)          \
	class Safe_##handleName {                           \
		handleName *h;                                  \
                                                        \
	   public:                                          \
		Safe_##handleName() { h = nullptr; }            \
		Safe_##handleName(handleName *hIn) { h = hIn; } \
		~Safe_##handleName() { freeFunction(h); }       \
		handleName *Set(handleName *hIn)                \
		{                                               \
			if (h != nullptr) {                         \
				freeFunction(h);                        \
			}                                           \
			h = hIn;                                    \
			if (hIn != nullptr) {                       \
				handleName##_up_ref(hIn);               \
			}                                           \
			return hIn;                                 \
		}                                               \
		bool IsNull() { return h == NULL; }             \
		operator handleName *() { return h; }           \
		handleName *operator=(handleName *pIn)          \
		{                                               \
			Set(pIn);                                   \
			return pIn;                                 \
		}                                               \
		handleName *Transfer(Safe_##handleName *hIn)    \
		{                                               \
			if (h != nullptr) {                         \
				freeFunction(h);                        \
			}                                           \
			h = hIn->h;                                 \
			hIn->h = nullptr;                           \
			return h;                                   \
		}                                               \
		handleName *operator=(Safe_##handleName hIn)    \
		{                                               \
			Set(hIn.h);                                 \
			return h;                                   \
		}                                               \
		handleName *Release()                           \
		{                                               \
			handleName *h2 = h;                         \
			h = nullptr;                                \
			return h2;                                  \
		}                                               \
	};

Safe_OPENSSL(EC_KEY, EC_KEY_free);
Safe_OPENSSL(EVP_PKEY, EVP_PKEY_free);

/**********************************************/

bool AES_CCM_Decrypt(COSE_Enveloped *pcose,
	int TSize,
	int LSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbCrypto,
	size_t cbCrypto,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	EVP_CIPHER_CTX *ctx;
	int cbOut;
	byte *rgbOut = nullptr;
	size_t NSize = 15 - (LSize / 8);
	int outl = 0;
	byte rgbIV[15] = {0};
	const cn_cbor *pIV = nullptr;
	const EVP_CIPHER *cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(ctx != nullptr, COSE_ERR_OUT_OF_MEMORY);

	//  Setup the IV/Nonce and put it into the message

	pIV = _COSE_map_get_int(
		&pcose->m_message, COSE_Header_IV, COSE_BOTH, nullptr);
	if ((pIV == nullptr) || (pIV->type != CN_CBOR_BYTES)) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_INVALID_PARAMETER;
		}

	errorReturn:
		if (rgbOut != nullptr) {
			COSE_FREE(rgbOut, context);
		}
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	CHECK_CONDITION(pIV->length == NSize, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbIV, pIV->v.str, pIV->length);

	//  Setup and run the OpenSSL code

	switch (cbKey) {
		case 128 / 8:
			cipher = EVP_aes_128_ccm();
			break;

		case 192 / 8:
			cipher = EVP_aes_192_ccm();
			break;

		case 256 / 8:
			cipher = EVP_aes_256_ccm();
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}
	CHECK_CONDITION(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr),
		COSE_ERR_DECRYPT_FAILED);

	TSize /= 8;	 // Comes in in bits not bytes.
	CHECK_CONDITION(
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, (LSize / 8), 0),
		COSE_ERR_DECRYPT_FAILED);
	// CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize,
	// 0), COSE_ERR_DECRYPT_FAILED);
	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TSize,
						(void *)&pbCrypto[cbCrypto - TSize]),
		COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptInit_ex(ctx, 0, nullptr, pbKey, rgbIV),
		COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(
		EVP_DecryptUpdate(ctx, nullptr, &cbOut, nullptr, (int)cbCrypto - TSize),
		COSE_ERR_DECRYPT_FAILED);

	cbOut = (int)cbCrypto - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		EVP_DecryptUpdate(ctx, nullptr, &outl, pbAuthData, (int)cbAuthData),
		COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(
		EVP_DecryptUpdate(ctx, rgbOut, &cbOut, pbCrypto, (int)cbCrypto - TSize),
		COSE_ERR_DECRYPT_FAILED);

	EVP_CIPHER_CTX_free(ctx);

	pcose->pbContent = rgbOut;
	pcose->cbContent = cbOut;

	return true;
}

bool AES_CCM_Encrypt(COSE_Enveloped *pcose,
	int TSize,
	int LSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	EVP_CIPHER_CTX *ctx;
	int cbOut;
	byte *rgbOut = nullptr;
	size_t NSize = 15 - (LSize / 8);
	int outl = 0;
	const cn_cbor *cbor_iv = nullptr;
	cn_cbor *cbor_iv_t = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
	cn_cbor *cnTmp = nullptr;
	const EVP_CIPHER *cipher;
	byte rgbIV[16];
	byte *pbIV = nullptr;
	cn_cbor_errback cbor_error;

	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

	switch (cbKey * 8) {
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

	cbor_iv =
		_COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, perr);
	if (cbor_iv == nullptr) {
		pbIV = (byte *)COSE_CALLOC(NSize, 1, context);
		CHECK_CONDITION(pbIV != nullptr, COSE_ERR_OUT_OF_MEMORY);
		rand_bytes(pbIV, NSize);
		memcpy(rgbIV, pbIV, NSize);
		cbor_iv_t = cn_cbor_data_create2(
			pbIV, NSize, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cbor_iv_t != nullptr, cbor_error);
		pbIV = nullptr;

		if (!_COSE_map_put(&pcose->m_message, COSE_Header_IV, cbor_iv_t,
				COSE_UNPROTECT_ONLY, perr)) {
			goto errorReturn;
		}
		cbor_iv_t = nullptr;
	}
	else {
		CHECK_CONDITION(
			cbor_iv->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(cbor_iv->length == NSize, COSE_ERR_INVALID_PARAMETER);
		memcpy(rgbIV, cbor_iv->v.str, cbor_iv->length);
	}

	//  Setup and run the OpenSSL code

	CHECK_CONDITION(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr),
		COSE_ERR_CRYPTO_FAIL);

	TSize /= 8;	 // Comes in in bits not bytes.
	CHECK_CONDITION(
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, (LSize / 8), 0),
		COSE_ERR_CRYPTO_FAIL);
	// CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize,
	// 0), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TSize, nullptr),
		COSE_ERR_CRYPTO_FAIL);	// Say we are doing an 8 byte tag

	CHECK_CONDITION(EVP_EncryptInit_ex(ctx, 0, nullptr, pbKey, rgbIV),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptUpdate(ctx, 0, &cbOut, 0, (int)pcose->cbContent),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(
		EVP_EncryptUpdate(ctx, nullptr, &outl, pbAuthData, (int)cbAuthData),
		COSE_ERR_CRYPTO_FAIL);

	rgbOut = (byte *)COSE_CALLOC(cbOut + TSize, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbOut, &cbOut, pcose->pbContent,
						(int)pcose->cbContent),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(
		EVP_EncryptFinal_ex(ctx, &rgbOut[cbOut], &cbOut), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TSize,
						&rgbOut[pcose->cbContent]),
		COSE_ERR_CRYPTO_FAIL);

	cnTmp = cn_cbor_data_create2(rgbOut, (int)pcose->cbContent + TSize, 0,
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
	rgbOut = nullptr;

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);
	cnTmp = nullptr;
	EVP_CIPHER_CTX_free(ctx);
	return true;

errorReturn:
	if (pbIV != nullptr) {
		COSE_FREE(pbIV, context);
	}
	if (cbor_iv_t != nullptr) {
		COSE_FREE(cbor_iv_t, context);
	}
	if (rgbOut != nullptr) {
		COSE_FREE(rgbOut, context);
	}
	if (cnTmp != nullptr) {
		COSE_FREE(cnTmp, context);
	}
	EVP_CIPHER_CTX_free(ctx);
	return false;
}

bool AES_GCM_Decrypt(COSE_Enveloped *pcose,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbCrypto,
	size_t cbCrypto,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	EVP_CIPHER_CTX *ctx;
	int cbOut;
	byte *rgbOut = nullptr;
	int outl = 0;
	byte rgbIV[15] = {0};
	const cn_cbor *pIV = nullptr;
	const EVP_CIPHER *cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
	int TSize = 128 / 8;

	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

	//  Setup the IV/Nonce and put it into the message

	pIV = _COSE_map_get_int(
		&pcose->m_message, COSE_Header_IV, COSE_BOTH, nullptr);
	if ((pIV == nullptr) || (pIV->type != CN_CBOR_BYTES)) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_INVALID_PARAMETER;
		}

	errorReturn:
		if (rgbOut != nullptr) {
			COSE_FREE(rgbOut, context);
		}
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	CHECK_CONDITION(pIV->length == 96 / 8, COSE_ERR_INVALID_PARAMETER);
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

	CHECK_CONDITION(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr),
		COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TSize,
						(void *)&pbCrypto[cbCrypto - TSize]),
		COSE_ERR_DECRYPT_FAILED);

	CHECK_CONDITION(EVP_DecryptInit_ex(ctx, 0, nullptr, pbKey, rgbIV),
		COSE_ERR_DECRYPT_FAILED);

	//  Pus in the AAD

	CHECK_CONDITION(
		EVP_DecryptUpdate(ctx, nullptr, &outl, pbAuthData, (int)cbAuthData),
		COSE_ERR_DECRYPT_FAILED);

	//

	cbOut = (int)cbCrypto - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	//  Process content

	CHECK_CONDITION(
		EVP_DecryptUpdate(ctx, rgbOut, &cbOut, pbCrypto, (int)cbCrypto - TSize),
		COSE_ERR_DECRYPT_FAILED);

	//  Process Tag

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TSize,
						(byte *)pbCrypto + cbCrypto - TSize),
		COSE_ERR_DECRYPT_FAILED);

	//  Check the result

	CHECK_CONDITION(
		EVP_DecryptFinal(ctx, rgbOut + cbOut, &cbOut), COSE_ERR_DECRYPT_FAILED);

	EVP_CIPHER_CTX_free(ctx);

	pcose->pbContent = rgbOut;
	pcose->cbContent = cbOut;

	return true;
}

bool AES_GCM_Encrypt(COSE_Enveloped *pcose,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	EVP_CIPHER_CTX *ctx;
	int cbOut;
	byte *rgbOut = nullptr;
	int outl = 0;
	byte rgbIV[16] = {0};
	byte *pbIV = nullptr;
	const cn_cbor *cbor_iv = nullptr;
	cn_cbor *cbor_iv_t = nullptr;
	const EVP_CIPHER *cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
	cn_cbor_errback cbor_error;

	if (false) {
	errorReturn:
		if (pbIV != nullptr) {
			COSE_FREE(pbIV, context);
		}
		if (cbor_iv_t != nullptr) {
			CN_CBOR_FREE(cbor_iv_t, context);
		}
		if (rgbOut != nullptr) {
			COSE_FREE(rgbOut, context);
		}
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	// Make it first so we can clean it up
	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

	//  Setup the IV/Nonce and put it into the message

	cbor_iv =
		_COSE_map_get_int(&pcose->m_message, COSE_Header_IV, COSE_BOTH, perr);
	if (cbor_iv == nullptr) {
		pbIV = (byte *)COSE_CALLOC(96, 1, context);
		CHECK_CONDITION(pbIV != nullptr, COSE_ERR_OUT_OF_MEMORY);
		rand_bytes(pbIV, 96 / 8);
		memcpy(rgbIV, pbIV, 96 / 8);
		cbor_iv_t = cn_cbor_data_create2(
			pbIV, 96 / 8, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cbor_iv_t != nullptr, cbor_error);
		pbIV = nullptr;

		if (!_COSE_map_put(&pcose->m_message, COSE_Header_IV, cbor_iv_t,
				COSE_UNPROTECT_ONLY, perr)) {
			goto errorReturn;
		}
		cbor_iv_t = nullptr;
	}
	else {
		CHECK_CONDITION(
			cbor_iv->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(cbor_iv->length == 96 / 8, COSE_ERR_INVALID_PARAMETER);
		memcpy(rgbIV, cbor_iv->v.str, cbor_iv->length);
	}

	switch (cbKey * 8) {
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

	CHECK_CONDITION(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_EncryptInit_ex(ctx, 0, nullptr, pbKey, rgbIV),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(
		EVP_EncryptUpdate(ctx, nullptr, &outl, pbAuthData, (int)cbAuthData),
		COSE_ERR_CRYPTO_FAIL);

	rgbOut = (byte *)COSE_CALLOC(pcose->cbContent + 128 / 8, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbOut, &cbOut, pcose->pbContent,
						(int)pcose->cbContent),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(
		EVP_EncryptFinal_ex(ctx, &rgbOut[cbOut], &cbOut), COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 128 / 8,
						&rgbOut[pcose->cbContent]),
		COSE_ERR_CRYPTO_FAIL);

	cn_cbor *cnTmp = cn_cbor_data_create2(rgbOut,
		(int)pcose->cbContent + 128 / 8, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
	rgbOut = nullptr;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	EVP_CIPHER_CTX_free(ctx);

	if (pbIV != nullptr) {
		COSE_FREE(pbIV, context);
	}
	return true;
}

bool AES_CBC_MAC_Create(COSE_MacMessage *pcose,
	int TSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	const EVP_CIPHER *pcipher = nullptr;
	EVP_CIPHER_CTX *ctx;
	int cbOut;
	byte rgbIV[16] = {0};
	byte *rgbOut = nullptr;
	bool f = false;
	unsigned int i;
	cn_cbor *cn = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

	rgbOut = (byte *)COSE_CALLOC(16, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	switch (cbKey * 8) {
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

	CHECK_CONDITION(EVP_EncryptInit_ex(ctx, pcipher, nullptr, pbKey, rgbIV),
		COSE_ERR_CRYPTO_FAIL);

	for (i = 0; i < (unsigned int)cbAuthData / 16; i++) {
		CHECK_CONDITION(
			EVP_EncryptUpdate(ctx, rgbOut, &cbOut, pbAuthData + (i * 16), 16),
			COSE_ERR_CRYPTO_FAIL);
	}
	if (cbAuthData % 16 != 0) {
		CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbOut, &cbOut,
							pbAuthData + (i * 16), cbAuthData % 16),
			COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(EVP_EncryptUpdate(
							ctx, rgbOut, &cbOut, rgbIV, 16 - (cbAuthData % 16)),
			COSE_ERR_CRYPTO_FAIL);
	}

	cn = cn_cbor_data_create2(
		rgbOut, TSize / 8, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cn != nullptr, COSE_ERR_OUT_OF_MEMORY);
	rgbOut = nullptr;

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cn, INDEX_MAC_TAG,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);
	cn = nullptr;

	EVP_CIPHER_CTX_free(ctx);
	return !f;

errorReturn:
	if (rgbOut != nullptr) {
		COSE_FREE(rgbOut, context);
	}
	if (cn != nullptr) {
		CN_CBOR_FREE(cn, context);
	}
	EVP_CIPHER_CTX_free(ctx);
	return false;
}

bool AES_CBC_MAC_Validate(COSE_MacMessage *pcose,
	int TSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	const EVP_CIPHER *pcipher = nullptr;
	EVP_CIPHER_CTX *ctx = nullptr;
	int cbOut;
	byte rgbIV[16] = {0};
	byte rgbTag[16] = {0};
	bool f = false;
	unsigned int i;

	if (false) {
	errorReturn:
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	switch (cbKey * 8) {
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

	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(EVP_EncryptInit_ex(ctx, pcipher, nullptr, pbKey, rgbIV),
		COSE_ERR_CRYPTO_FAIL);

	TSize /= 8;

	for (i = 0; i < (unsigned int)cbAuthData / 16; i++) {
		CHECK_CONDITION(
			EVP_EncryptUpdate(ctx, rgbTag, &cbOut, pbAuthData + (i * 16), 16),
			COSE_ERR_CRYPTO_FAIL);
	}
	if (cbAuthData % 16 != 0) {
		CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbTag, &cbOut,
							pbAuthData + (i * 16), cbAuthData % 16),
			COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(EVP_EncryptUpdate(
							ctx, rgbTag, &cbOut, rgbIV, 16 - (cbAuthData % 16)),
			COSE_ERR_CRYPTO_FAIL);
	}

	cn_cbor *cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != nullptr, COSE_ERR_CBOR);

	for (i = 0; i < (unsigned int)TSize; i++) {
		f |= (cn->v.bytes[i] != rgbTag[i]);
	}

	EVP_CIPHER_CTX_free(ctx);
	return !f;
}

#if 0
//  We are doing CBC-MAC not CMAC at this time
bool AES_CMAC_Validate(COSE_MacMessage * pcose, int KeySize, int TagSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr)
{
	CMAC_CTX * pctx = nullptr;
	const EVP_CIPHER * pcipher = nullptr;
	byte * rgbOut = nullptr;
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
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(CMAC_Init(pctx, pcose->pbKey, pcose->cbKey, pcipher, nullptr /*impl*/) == 1, COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(CMAC_Update(pctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(CMAC_Final(pctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

	cn_cbor * cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != nullptr, COSE_ERR_CBOR);

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

bool HKDF_AES_Expand(COSE *pcose,
	size_t cbitKey,
	const byte *pbPRK,
	size_t cbPRK,
	const byte *pbInfo,
	size_t cbInfo,
	byte *pbOutput,
	size_t cbOutput,
	cose_errback *perr)
{
	const EVP_CIPHER *pcipher = nullptr;
	EVP_CIPHER_CTX *ctx;
	int cbOut;
	byte rgbIV[16] = {0};
	byte bCount = 1;
	size_t ib;
	byte rgbDigest[128 / 8];
	int cbDigest = 0;
	byte rgbOut[16];

	UNUSED(pcose);

	ctx = EVP_CIPHER_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

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
	CHECK_CONDITION(cbPRK == cbitKey / 8, COSE_ERR_INVALID_PARAMETER);

	//  Setup and run the OpenSSL code

	for (ib = 0; ib < cbOutput; ib += 16, bCount += 1) {
		size_t ib2;

		CHECK_CONDITION(EVP_EncryptInit_ex(ctx, pcipher, nullptr, pbPRK, rgbIV),
			COSE_ERR_CRYPTO_FAIL);

		CHECK_CONDITION(
			EVP_EncryptUpdate(ctx, rgbOut, &cbOut, rgbDigest, cbDigest),
			COSE_ERR_CRYPTO_FAIL);
		for (ib2 = 0; ib2 < cbInfo; ib2 += 16) {
			CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbOut, &cbOut, pbInfo + ib2,
								(int)COSE_MIN(16, cbInfo - ib2)),
				COSE_ERR_CRYPTO_FAIL);
		}
		CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbOut, &cbOut, &bCount, 1),
			COSE_ERR_CRYPTO_FAIL);
		if ((cbInfo + 1) % 16 != 0) {
			CHECK_CONDITION(EVP_EncryptUpdate(ctx, rgbOut, &cbOut, rgbIV,
								(int)16 - (cbInfo + 1) % 16),
				COSE_ERR_CRYPTO_FAIL);
		}
		memcpy(rgbDigest, rgbOut, cbOut);
		cbDigest = cbOut;
		memcpy(pbOutput + ib, rgbDigest, COSE_MIN(16, cbOutput - ib));
	}

	EVP_CIPHER_CTX_free(ctx);
	return true;

errorReturn:
	EVP_CIPHER_CTX_free(ctx);
	return false;
}

bool HKDF_Extract(COSE *pcose,
	const byte *pbKey,
	size_t cbKey,
	size_t cbitDigest,
	byte *rgbDigest,
	size_t *pcbDigest,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	UNUSED(context);
#endif
	byte rgbSalt[EVP_MAX_MD_SIZE] = {0};
	int cbSalt;
	cn_cbor *cnSalt;
	HMAC_CTX *ctx;
	const EVP_MD *pmd = nullptr;
	unsigned int cbDigest;

	ctx = HMAC_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

	if (0) {
	errorReturn:
		HMAC_CTX_free(ctx);
		return false;
	}

	switch (cbitDigest) {
		case 256:
			pmd = EVP_sha256();
			cbSalt = 256 / 8;
			break;
		case 384:
			pmd = EVP_sha384();
			cbSalt = 384 / 8;
			break;
		case 512:
			pmd = EVP_sha512();
			cbSalt = 512 / 8;
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	cnSalt = _COSE_map_get_int(pcose, COSE_Header_HKDF_salt, COSE_BOTH, perr);

	if (cnSalt != nullptr) {
		CHECK_CONDITION(HMAC_Init_ex(ctx, cnSalt->v.bytes, (int)cnSalt->length,
							pmd, nullptr),
			COSE_ERR_CRYPTO_FAIL);
	}
	else {
		CHECK_CONDITION(HMAC_Init_ex(ctx, rgbSalt, cbSalt, pmd, nullptr),
			COSE_ERR_CRYPTO_FAIL);
	}
	CHECK_CONDITION(HMAC_Update(ctx, pbKey, (int)cbKey), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		HMAC_Final(ctx, rgbDigest, &cbDigest), COSE_ERR_CRYPTO_FAIL);
	*pcbDigest = cbDigest;
	HMAC_CTX_free(ctx);
	return true;
}

bool HKDF_Expand(COSE *pcose,
	size_t cbitDigest,
	const byte *pbPRK,
	size_t cbPRK,
	const byte *pbInfo,
	size_t cbInfo,
	byte *pbOutput,
	size_t cbOutput,
	cose_errback *perr)
{
	HMAC_CTX *ctx;
	const EVP_MD *pmd = nullptr;
	size_t ib;
	unsigned int cbDigest = 0;
	byte rgbDigest[EVP_MAX_MD_SIZE];
	byte bCount = 1;

	UNUSED(pcose);

	ctx = HMAC_CTX_new();
	CHECK_CONDITION(ctx != nullptr, COSE_ERR_OUT_OF_MEMORY);

	if (0) {
	errorReturn:
		HMAC_CTX_free(ctx);
		return false;
	}

	switch (cbitDigest) {
		case 256:
			pmd = EVP_sha256();
			break;
		case 384:
			pmd = EVP_sha384();
			break;
		case 512:
			pmd = EVP_sha512();
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	for (ib = 0; ib < cbOutput; ib += cbDigest, bCount += 1) {
		CHECK_CONDITION(HMAC_Init_ex(ctx, pbPRK, (int)cbPRK, pmd, nullptr),
			COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(
			HMAC_Update(ctx, rgbDigest, cbDigest), COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(HMAC_Update(ctx, pbInfo, cbInfo), COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(HMAC_Update(ctx, &bCount, 1), COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(
			HMAC_Final(ctx, rgbDigest, &cbDigest), COSE_ERR_CRYPTO_FAIL);

		memcpy(pbOutput + ib, rgbDigest, COSE_MIN(cbDigest, cbOutput - ib));
	}

	HMAC_CTX_free(ctx);
	return true;
}

bool HMAC_Create(COSE_MacMessage *pcose,
	int HSize,
	int TSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	HMAC_CTX *ctx;
	const EVP_MD *pmd = nullptr;
	byte *rgbOut = nullptr;
	unsigned int cbOut;
	cn_cbor *cbor = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	ctx = HMAC_CTX_new();
	CHECK_CONDITION(nullptr != ctx, COSE_ERR_OUT_OF_MEMORY);

	if (0) {
	errorReturn:
		COSE_FREE(rgbOut, context);
		if (cbor != nullptr) {
			COSE_FREE(cbor, context);
		}
		HMAC_CTX_free(ctx);
		return false;
	}

	switch (HSize) {
		case 256:
			pmd = EVP_sha256();
			break;
		case 384:
			pmd = EVP_sha384();
			break;
		case 512:
			pmd = EVP_sha512();
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	rgbOut = (byte *)COSE_CALLOC(EVP_MAX_MD_SIZE, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(HMAC_Init_ex(ctx, pbKey, (int)cbKey, pmd, nullptr),
		COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		HMAC_Update(ctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Final(ctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

	cbor = cn_cbor_data_create2(
		rgbOut, TSize / 8, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cbor != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cbor, INDEX_MAC_TAG,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	HMAC_CTX_free(ctx);
	return true;
}

bool HMAC_Validate(COSE_MacMessage *pcose,
	int HSize,
	int TSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	HMAC_CTX *ctx = nullptr;
	const EVP_MD *pmd = nullptr;
	byte *rgbOut = nullptr;
	unsigned int cbOut = 0;
	bool f = false;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	if (false) {
	errorReturn:
		if (rgbOut != nullptr) {
			COSE_FREE(rgbOut, context);
		}
		HMAC_CTX_free(ctx);
		return false;
	}
	ctx = HMAC_CTX_new();
	CHECK_CONDITION(ctx != nullptr, COSE_ERR_OUT_OF_MEMORY);

	switch (HSize) {
		case 256:
			pmd = EVP_sha256();
			break;
		case 384:
			pmd = EVP_sha384();
			break;
		case 512:
			pmd = EVP_sha512();
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	rgbOut = (byte *)COSE_CALLOC(EVP_MAX_MD_SIZE, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(HMAC_Init_ex(ctx, pbKey, (int)cbKey, pmd, nullptr),
		COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		HMAC_Update(ctx, pbAuthData, cbAuthData), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(HMAC_Final(ctx, rgbOut, &cbOut), COSE_ERR_CRYPTO_FAIL);

	cn_cbor *cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != nullptr, COSE_ERR_CBOR);

	if (cn->length > cbOut) {
		f = false;
	}
	else {
		for (unsigned int i = 0; i < (unsigned int)TSize / 8; i++) {
			f |= (cn->v.bytes[i] != rgbOut[i]);
		}
	}

	COSE_FREE(rgbOut, context);
	HMAC_CTX_free(ctx);
	return !f;
}

#define COSE_Key_EC_Curve -1
#define COSE_Key_EC_X -2
#define COSE_Key_EC_Y -3
#define COSE_Key_EC_d -4

EVP_PKEY *EVP_FromKey(COSE_KEY *pKey, CBOR_CONTEXT_COMMA cose_errback *perr)
{
	if (pKey->m_opensslKey != nullptr) {
		return pKey->m_opensslKey;
	}

	if (false) {
	errorReturn:
		return nullptr;
	}

	cn_cbor *keyType = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_Type);
	CHECK_CONDITION(keyType != NULL && keyType->type == CN_CBOR_UINT,
		COSE_ERR_INVALID_PARAMETER);

	switch (keyType->v.uint) {
		case COSE_Key_Type_EC2: {
			int cbSize;
			Safe_EC_KEY ecKey = ECKey_From(pKey, &cbSize, perr);
			CHECK_CONDITION(ecKey != nullptr, perr->err);
			Safe_EVP_PKEY evpKey = EVP_PKEY_new();
			CHECK_CONDITION(evpKey != nullptr, COSE_ERR_OUT_OF_MEMORY);
			CHECK_CONDITION(
				EVP_PKEY_set1_EC_KEY(evpKey, ecKey) == 1, COSE_ERR_CRYPTO_FAIL);
			pKey->m_opensslKey = evpKey;
			EVP_PKEY_up_ref(pKey->m_opensslKey);
			return evpKey.Release();
		}

		case COSE_Key_Type_OKP: {
			int type;
			cn_cbor *p =
				cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_OPK_Curve);
			CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);

			switch (p->v.uint) {
				case COSE_Curve_Ed25519:
					type = EVP_PKEY_ED25519;
					break;

				case COSE_Curve_Ed448:
					type = EVP_PKEY_ED448;
					break;

				case COSE_Curve_X25519:
					type = EVP_PKEY_X25519;
					break;

				case COSE_Curve_X448:
					type = EVP_PKEY_X448;
					break;

				default:
					FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			}

			Safe_EVP_PKEY evpKey;

			p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_d);
			if (p != nullptr) {
				evpKey = EVP_PKEY_new_raw_private_key(
					type, nullptr, p->v.bytes, p->length);
				CHECK_CONDITION(evpKey != nullptr, COSE_ERR_CRYPTO_FAIL);
			}
			else {
				p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_OPK_X);
				CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);
				evpKey = EVP_PKEY_new_raw_public_key(
					type, nullptr, p->v.bytes, p->length);
			}

			pKey->m_opensslKey = evpKey;
			EVP_PKEY_up_ref(pKey->m_opensslKey);
			return evpKey.Release();
		}

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
}

EC_KEY *ECKey_From(COSE_KEY *pKey, int *cbGroup, cose_errback *perr)
{
	if (false) {
	errorReturn:
		return nullptr;
	}

	if (pKey->m_opensslKey != nullptr) {
		Safe_EC_KEY pKeyNew = EVP_PKEY_get1_EC_KEY(pKey->m_opensslKey);
		CHECK_CONDITION(pKeyNew != nullptr, COSE_ERR_INVALID_PARAMETER);
		int gid = EC_GROUP_get_curve_name(EC_KEY_get0_group(pKeyNew));
		switch (gid) {
			case NID_X9_62_prime256v1:
				*cbGroup = 256 / 8;
				break;

			case NID_secp384r1:
				*cbGroup = 384 / 8;
				break;

			case NID_secp521r1:
				*cbGroup = (521 + 7) / 8;
				break;

			default:
				FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
		}

		return pKeyNew.Release();
	}

	byte rgbKey[512 + 1];
	int cbKey;
	const cn_cbor *p;
	int nidGroup = -1;
	EC_POINT *pPoint = nullptr;

	Safe_EC_KEY pNewKey = EC_KEY_new();
	CHECK_CONDITION(pNewKey != nullptr, COSE_ERR_OUT_OF_MEMORY);

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_Curve);
	CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);

	switch (p->v.sint) {
		case 1:	 // P-256
			nidGroup = NID_X9_62_prime256v1;
			*cbGroup = 256 / 8;
			break;

		case 2:	 // P-384
			nidGroup = NID_secp384r1;
			*cbGroup = 384 / 8;
			break;

		case 3:	 // P-521
			nidGroup = NID_secp521r1;
			*cbGroup = (521 + 7) / 8;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(nidGroup);
	CHECK_CONDITION(ecgroup != nullptr, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(
		EC_KEY_set_group(pNewKey, ecgroup) == 1, COSE_ERR_CRYPTO_FAIL);

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_X);
	CHECK_CONDITION((p != nullptr) && (p->type == CN_CBOR_BYTES),
		COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(p->length == (size_t)*cbGroup, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbKey + 1, p->v.str, p->length);

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_Y);
	CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);
	if (p->type == CN_CBOR_BYTES) {
		rgbKey[0] = POINT_CONVERSION_UNCOMPRESSED;
		cbKey = (*cbGroup * 2) + 1;
		CHECK_CONDITION(
			p->length == (size_t)*cbGroup, COSE_ERR_INVALID_PARAMETER);
		memcpy(rgbKey + p->length + 1, p->v.str, p->length);
	}
	else if (p->type == CN_CBOR_TRUE) {
		cbKey = (*cbGroup) + 1;
		rgbKey[0] = POINT_CONVERSION_COMPRESSED + 1;
	}
	else if (p->type == CN_CBOR_FALSE) {
		cbKey = (*cbGroup) + 1;
		rgbKey[0] = POINT_CONVERSION_COMPRESSED;
	}
	else {
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	pPoint = EC_POINT_new(ecgroup);
	CHECK_CONDITION(pPoint != nullptr, COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		EC_POINT_oct2point(ecgroup, pPoint, rgbKey, cbKey, nullptr) == 1,
		COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		EC_KEY_set_public_key(pNewKey, pPoint) == 1, COSE_ERR_CRYPTO_FAIL);

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_d);
	if (p != nullptr) {
		BIGNUM *pbn = BN_bin2bn(p->v.bytes, (int)p->length, nullptr);
		CHECK_CONDITION(pbn != nullptr, COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION(
			EC_KEY_set_private_key(pNewKey, pbn) == 1, COSE_ERR_CRYPTO_FAIL);
	}

	pKey->m_opensslKey = EVP_PKEY_new();
	CHECK_CONDITION(pKey->m_opensslKey != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_PKEY_set1_EC_KEY(pKey->m_opensslKey, pNewKey) == 1,
		COSE_ERR_CRYPTO_FAIL);

	return pNewKey.Release();
}

cn_cbor *EC_ToCBOR(const EC_KEY *pKey,
	bool fUseCompressed,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	cn_cbor *pkey = nullptr;
	int cose_group;
	cn_cbor *p = nullptr;
	cn_cbor_errback cbor_error;
	byte *pbPoint = nullptr;
	size_t cbSize;
	byte *pbOut = nullptr;
	size_t cbX;
	const EC_POINT *pPoint = nullptr;

	const EC_GROUP *pgroup = EC_KEY_get0_group(pKey);
	CHECK_CONDITION(pgroup != nullptr, COSE_ERR_INVALID_PARAMETER);

	switch (EC_GROUP_get_curve_name(pgroup)) {
		case NID_X9_62_prime256v1:
			cose_group = 1;
			break;
		case NID_secp384r1:
			cose_group = 2;
			break;
		case NID_secp521r1:
			cose_group = 3;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	pkey = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(pkey != nullptr, cbor_error);

	p = cn_cbor_int_create(cose_group, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_Curve, p,
							 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
		cbor_error);
	p = nullptr;

	pPoint = EC_KEY_get0_public_key(pKey);
	CHECK_CONDITION(pPoint != nullptr, COSE_ERR_INVALID_PARAMETER);

	if (fUseCompressed) {
		cbSize = EC_POINT_point2oct(
			pgroup, pPoint, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
		CHECK_CONDITION(cbSize > 0, COSE_ERR_CRYPTO_FAIL);
		pbPoint = (byte *)COSE_CALLOC(cbSize, 1, context);
		CHECK_CONDITION(pbPoint != nullptr, COSE_ERR_OUT_OF_MEMORY);
		CHECK_CONDITION(
			EC_POINT_point2oct(pgroup, pPoint, POINT_CONVERSION_COMPRESSED,
				pbPoint, cbSize, nullptr) == cbSize,
			COSE_ERR_CRYPTO_FAIL);
		cbX = cbSize - 1;
	}
	else {
		cbSize = EC_POINT_point2oct(
			pgroup, pPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
		CHECK_CONDITION(cbSize > 0, COSE_ERR_CRYPTO_FAIL);
		pbPoint = (byte *)COSE_CALLOC(cbSize, 1, context);
		CHECK_CONDITION(pbPoint != nullptr, COSE_ERR_OUT_OF_MEMORY);
		CHECK_CONDITION(
			EC_POINT_point2oct(pgroup, pPoint, POINT_CONVERSION_UNCOMPRESSED,
				pbPoint, cbSize, nullptr) == cbSize,
			COSE_ERR_CRYPTO_FAIL);
		cbX = cbSize / 2;
	}

	pbOut = (byte *)COSE_CALLOC((int)(cbX), 1, context);
	CHECK_CONDITION(pbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);
	memcpy(pbOut, pbPoint + 1, (int)(cbX));
	p = cn_cbor_data_create2(
		pbOut, (int)(cbX), 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
	pbOut = nullptr;
	CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_X, p,
							 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
		cbor_error);
	p = nullptr;

	if (fUseCompressed) {
		p = cn_cbor_bool_create(
			pbPoint[0] & 1, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_Y, p,
								 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
			cbor_error);
		p = nullptr;
	}
	else {
		pbOut = (byte *)COSE_CALLOC((int)(cbX), 1, context);
		CHECK_CONDITION(pbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);
		memcpy(pbOut, pbPoint + cbSize / 2 + 1, (int)(cbX));
		p = cn_cbor_data_create2(
			pbOut, (int)(cbX), 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
		pbOut = nullptr;
		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_Y, p,
								 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
			cbor_error);
		p = nullptr;
	}

	p = cn_cbor_int_create(
		COSE_Key_Type_EC2, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_Type, p,
							 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
		cbor_error);
	p = nullptr;

returnHere:
	if (pbPoint != nullptr) {
		COSE_FREE(pbPoint, context);
	}
	if (pbOut != nullptr) {
		COSE_FREE(pbOut, context);
	}
	if (p != nullptr) {
		CN_CBOR_FREE(p, context);
	}
	return pkey;

errorReturn:
	CN_CBOR_FREE(pkey, context);
	pkey = nullptr;
	goto returnHere;
}

cn_cbor *EVP_ToCBOR(EVP_PKEY *pKey,
	bool fCompressPoints,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	cn_cbor_errback cborErr;
	int type = EVP_PKEY_base_id(pKey);

	switch (type) {
		case EVP_PKEY_EC:
			return EC_ToCBOR(EVP_PKEY_get1_EC_KEY(pKey), fCompressPoints,
				CBOR_CONTEXT_PARAM_COMMA perr);

		case EVP_PKEY_X25519:
		case EVP_PKEY_X448: {
			cn_cbor *pkey = nullptr;
			cn_cbor *temp = nullptr;
			unsigned char *pbKey = nullptr;
			if (false) {
			errorReturn:
				if (pkey != nullptr) {
					CN_CBOR_FREE(pkey, context);
				}
				if (temp != nullptr) {
					CN_CBOR_FREE(temp, context);
				}
				if (pbKey != nullptr) {
					COSE_FREE(pbKey, context);
				}
				return nullptr;
			}
			pkey = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & cborErr);
			CHECK_CONDITION_CBOR(pkey != nullptr, cborErr);
			temp = cn_cbor_int_create(
				COSE_Key_Type_OKP, CBOR_CONTEXT_PARAM_COMMA & cborErr);
			CHECK_CONDITION_CBOR(temp != nullptr, cborErr);
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_Type, temp,
									 CBOR_CONTEXT_PARAM_COMMA & cborErr),
				cborErr);
			temp = nullptr;
			temp = cn_cbor_int_create(
				type == EVP_PKEY_X25519 ? COSE_Curve_X25519 : COSE_Curve_X448,
				CBOR_CONTEXT_PARAM_COMMA & cborErr);
			CHECK_CONDITION_CBOR(temp != nullptr, cborErr);
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_OPK_Curve,
									 temp, CBOR_CONTEXT_PARAM_COMMA & cborErr),
				cborErr);
			temp = nullptr;
			size_t cbKey;
			CHECK_CONDITION(
				EVP_PKEY_get_raw_public_key(pKey, nullptr, &cbKey) == 1,
				COSE_ERR_CRYPTO_FAIL);
			pbKey = (unsigned char *)COSE_CALLOC(cbKey, 1, context);
			CHECK_CONDITION(pbKey != nullptr, COSE_ERR_OUT_OF_MEMORY);
			CHECK_CONDITION(
				EVP_PKEY_get_raw_public_key(pKey, pbKey, &cbKey) == 1,
				COSE_ERR_CRYPTO_FAIL);
			temp = cn_cbor_data_create2(
				pbKey, cbKey, 0, CBOR_CONTEXT_PARAM_COMMA & cborErr);
			CHECK_CONDITION(temp != nullptr, COSE_ERR_OUT_OF_MEMORY);
			pbKey = nullptr;
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_OPK_X, temp,
									 CBOR_CONTEXT_PARAM_COMMA & cborErr),
				cborErr);
			temp = nullptr;
			return pkey;
		} break;

		default:
			perr->err = COSE_ERR_INVALID_PARAMETER;
			return nullptr;
	}
}

#if false

COSE_KEY *EC_FromKey(EC_KEY *pKey, bool fUseCompressed, CBOR_CONTEXT_COMMA cose_errback *perr)
{
	COSE_KEY *coseKey = nullptr;
	cn_cbor *pkey =
		EC_ToCBOR(pKey, fUseCompressed, CBOR_CONTEXT_PARAM_COMMA perr);
	if (pkey == nullptr) {
		return nullptr;
	}

	Safe_EVP_PKEY evpKey = EVP_PKEY_new();
	CHECK_CONDITION(evpKey != nullptr, COSE_ERR_OUT_OF_MEMORY);
	
	CHECK_CONDITION(EVP_PKEY_set1_EC_KEY(evpKey, pKey) == 1, COSE_ERR_CRYPTO_FAIL);	

	coseKey =
		(COSE_KEY *)COSE_KEY_FromEVP(evpKey, pkey, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(coseKey != nullptr, COSE_ERR_OUT_OF_MEMORY);
	pkey = nullptr;

returnHere:
	if (pkey != nullptr) {
		CN_CBOR_FREE(pkey, context);
	}
	return coseKey;

errorReturn:
	goto returnHere;
}
#endif

bool ECDSA_Sign(COSE *pSigner,
	int index,
	COSE_KEY *pKey,
	int cbitDigest,
	const byte *rgbToSign,
	size_t cbToSign,
	cose_errback *perr)
{
	EC_KEY *eckey = nullptr;
	byte rgbDigest[EVP_MAX_MD_SIZE];
	unsigned int cbDigest = sizeof(rgbDigest);
	byte *pbSig = nullptr;
	const EVP_MD *digest;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_allocContext;
#endif
	cn_cbor *p = nullptr;
	ECDSA_SIG *psig = nullptr;
	cn_cbor_errback cbor_error;
	int cbR;
	byte rgbSig[66];
	int cb;

	eckey = ECKey_From(pKey, &cbR, perr);
	if (eckey == nullptr) {
	errorReturn:
		if (pbSig != nullptr) {
			COSE_FREE(pbSig, context);
		}
		if (p != nullptr) {
			CN_CBOR_FREE(p, context);
		}
		if (eckey != nullptr) {
			EC_KEY_free(eckey);
		}
		return false;
	}

	switch (cbitDigest) {
		case 256:
			digest = EVP_sha256();
			break;
		case 512:
			digest = EVP_sha512();
			break;
		case 384:
			digest = EVP_sha384();
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	EVP_Digest(rgbToSign, cbToSign, rgbDigest, &cbDigest, digest, nullptr);

	psig = ECDSA_do_sign(rgbDigest, cbDigest, eckey);
	CHECK_CONDITION(psig != nullptr, COSE_ERR_CRYPTO_FAIL);

	pbSig = (byte *)COSE_CALLOC(cbR, 2, context);
	CHECK_CONDITION(pbSig != nullptr, COSE_ERR_OUT_OF_MEMORY);

	const BIGNUM *r;
	const BIGNUM *s;
	ECDSA_SIG_get0(psig, &r, &s);
	cb = BN_bn2bin(r, rgbSig);
	CHECK_CONDITION(cb <= cbR, COSE_ERR_INVALID_PARAMETER);
	memcpy(pbSig + cbR - cb, rgbSig, cb);

	cb = BN_bn2bin(s, rgbSig);
	CHECK_CONDITION(cb <= cbR, COSE_ERR_INVALID_PARAMETER);
	memcpy(pbSig + 2 * cbR - cb, rgbSig, cb);

	p = cn_cbor_data_create2(
		pbSig, cbR * 2, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(p != nullptr, cbor_error);

	CHECK_CONDITION(_COSE_array_replace(
						pSigner, p, index, CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	pbSig = nullptr;

	if (eckey != nullptr) {
		EC_KEY_free(eckey);
	}

	return true;
}

bool ECDSA_Verify(COSE *pSigner,
	int index,
	COSE_KEY *pKey,
	int cbitDigest,
	const byte *rgbToSign,
	size_t cbToSign,
	cose_errback *perr)
{
	EC_KEY *eckey = nullptr;
	byte rgbDigest[EVP_MAX_MD_SIZE];
	unsigned int cbDigest = sizeof(rgbDigest);
	const EVP_MD *digest;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_allocContext;
#endif
	cn_cbor *p = nullptr;
	ECDSA_SIG *sig = nullptr;
	int cbR;
	cn_cbor *pSig;
	size_t cbSignature;

	BIGNUM *r, *s;

	eckey = ECKey_From(pKey, &cbR, perr);
	if (eckey == nullptr) {
	errorReturn:
		if (p != nullptr) {
			CN_CBOR_FREE(p, context);
		}
		if (eckey != nullptr) {
			EC_KEY_free(eckey);
		}
		if (sig != nullptr) {
			ECDSA_SIG_free(sig);
		}
		return false;
	}

	switch (cbitDigest) {
		case 256:
			digest = EVP_sha256();
			break;
		case 512:
			digest = EVP_sha512();
			break;
		case 384:
			digest = EVP_sha384();
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
	EVP_Digest(rgbToSign, cbToSign, rgbDigest, &cbDigest, digest, nullptr);

	pSig = _COSE_arrayget_int(pSigner, index);
	CHECK_CONDITION(pSig != nullptr, COSE_ERR_INVALID_PARAMETER);
	cbSignature = pSig->length;

	CHECK_CONDITION(cbSignature / 2 == (size_t)cbR, COSE_ERR_INVALID_PARAMETER);
	r = BN_bin2bn(pSig->v.bytes, (int)cbSignature / 2, nullptr);
	CHECK_CONDITION(nullptr != r, COSE_ERR_OUT_OF_MEMORY);
	s = BN_bin2bn(
		pSig->v.bytes + cbSignature / 2, (int)cbSignature / 2, nullptr);
	CHECK_CONDITION(nullptr != s, COSE_ERR_OUT_OF_MEMORY);

	sig = ECDSA_SIG_new();
	CHECK_CONDITION(sig != nullptr, COSE_ERR_OUT_OF_MEMORY);

	ECDSA_SIG_set0(sig, r, s);

	CHECK_CONDITION(ECDSA_do_verify(rgbDigest, cbDigest, sig, eckey) == 1,
		COSE_ERR_CRYPTO_FAIL);

	if (eckey != nullptr) {
		EC_KEY_free(eckey);
	}
	if (sig != nullptr) {
		ECDSA_SIG_free(sig);
	}

	return true;
}

#ifdef USE_EDDSA
bool EdDSA_Sign(COSE *pSigner,
	int index,
	COSE_KEY *pKeyIn,
	const byte *rgbToSign,
	size_t cbToSign,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_allocContext;
#endif
	cn_cbor *p;
	cn_cbor_errback cbor_error;
	EVP_PKEY_CTX *keyCtx = nullptr;
	EVP_MD_CTX *mdCtx = nullptr;
	Safe_EVP_PKEY pkey;
	byte *pbSig = nullptr;
	int cbSig;

	p = cn_cbor_mapget_int(pKeyIn->m_cborKey, COSE_Key_OPK_Curve);
	if (p == nullptr) {
	errorReturn:
		if (mdCtx != nullptr) {
			EVP_MD_CTX_free(mdCtx);
		}
		if (keyCtx != nullptr) {
			EVP_PKEY_CTX_free(keyCtx);
		}
		if (pbSig != nullptr) {
			COSE_FREE(pbSig, context);
		}
		return false;
	}

	int type;

	switch (p->v.uint) {
		case COSE_Curve_Ed25519:
			type = EVP_PKEY_ED25519;
			cbSig = 32 * 2;
			break;

		case COSE_Curve_Ed448:
			type = EVP_PKEY_ED448;
			cbSig = 64 * 2;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	pkey = EVP_FromKey(pKeyIn, CBOR_CONTEXT_PARAM_COMMA perr);
	if (pkey == nullptr) {
		goto errorReturn;
	}

	keyCtx = EVP_PKEY_CTX_new_id(type, nullptr);
	CHECK_CONDITION(keyCtx != nullptr, COSE_ERR_OUT_OF_MEMORY);

	mdCtx = EVP_MD_CTX_new();
	CHECK_CONDITION(mdCtx != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		EVP_DigestSignInit(mdCtx, &keyCtx, nullptr, nullptr, pkey) == 1,
		COSE_ERR_CRYPTO_FAIL);
	keyCtx = nullptr;

	pbSig = (byte *)COSE_CALLOC(cbSig, 1, context);
	CHECK_CONDITION(pbSig != nullptr, COSE_ERR_OUT_OF_MEMORY);

	size_t cb2 = cbSig;
	CHECK_CONDITION(
		EVP_DigestSign(mdCtx, pbSig, &cb2, rgbToSign, cbToSign) == 1,
		COSE_ERR_CRYPTO_FAIL);

	p = cn_cbor_data_create2(
		pbSig, (int)cb2, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION(p != nullptr, COSE_ERR_OUT_OF_MEMORY);
	pbSig = nullptr;

	CHECK_CONDITION(_COSE_array_replace(
						pSigner, p, index, CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	if (mdCtx != nullptr) {
		EVP_MD_CTX_free(mdCtx);
	}
	if (keyCtx != nullptr) {
		EVP_PKEY_CTX_free(keyCtx);
	}
	if (pbSig != nullptr) {
		COSE_FREE(pbSig, context);
	}

	return true;
}

bool EdDSA_Verify(COSE *pSigner,
	int index,
	COSE_KEY *pKey,
	const byte *rgbToSign,
	size_t cbToSign,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_allocContext;
#endif
	cn_cbor *pSig;
	Safe_EVP_PKEY pkey = nullptr;
	EVP_MD_CTX *pmdCtx = nullptr;

	cn_cbor *p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_OPK_Curve);
	if (p == nullptr) {
	errorReturn:
		if (pmdCtx != nullptr) {
			EVP_MD_CTX_free(pmdCtx);
		}
		return false;
	}

	int type;

	switch (p->v.uint) {
		case COSE_Curve_Ed25519:
			type = EVP_PKEY_ED25519;
			break;

		case COSE_Curve_Ed448:
			type = EVP_PKEY_ED448;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	pkey = EVP_FromKey(pKey, CBOR_CONTEXT_PARAM_COMMA perr);
	if (pkey == nullptr) {
		goto errorReturn;
	}

	pSig = _COSE_arrayget_int(pSigner, index);
	CHECK_CONDITION(pSig != nullptr, COSE_ERR_INVALID_PARAMETER);

	pmdCtx = EVP_MD_CTX_new();
	EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_id(type, nullptr);

	CHECK_CONDITION(
		EVP_DigestVerifyInit(pmdCtx, &keyCtx, nullptr, nullptr, pkey) == 1,
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(EVP_DigestVerify(pmdCtx, pSig->v.bytes, pSig->length,
						rgbToSign, cbToSign) == 1,
		COSE_ERR_CRYPTO_FAIL);

	if (pmdCtx != nullptr) {
		EVP_MD_CTX_free(pmdCtx);
	}

	return true;
}
#endif

bool AES_KW_Decrypt(COSE_Enveloped *pcose,
	const byte *pbKeyIn,
	size_t cbitKey,
	const byte *pbCipherText,
	size_t cbCipherText,
	byte *pbKeyOut,
	size_t *pcbKeyOut,
	cose_errback *perr)
{
	byte rgbOut[512 / 8];
	AES_KEY key;

	UNUSED(pcose);

	CHECK_CONDITION(AES_set_decrypt_key(pbKeyIn, (int)cbitKey, &key) == 0,
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(
		AES_unwrap_key(&key, nullptr, rgbOut, pbCipherText, (int)cbCipherText),
		COSE_ERR_CRYPTO_FAIL);

	memcpy(pbKeyOut, rgbOut, cbCipherText - 8);
	*pcbKeyOut = (int)(cbCipherText - 8);

	return true;
errorReturn:
	return false;
}

bool AES_KW_Encrypt(COSE_RecipientInfo *pcose,
	const byte *pbKeyIn,
	int cbitKey,
	const byte *pbContent,
	int cbContent,
	cose_errback *perr)
{
	byte *pbOut = nullptr;
	AES_KEY key;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_encrypt.m_message.m_allocContext;
#endif
	cn_cbor *cnTmp = nullptr;

	pbOut = (byte *)COSE_CALLOC(cbContent + 8, 1, context);
	CHECK_CONDITION(pbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		AES_set_encrypt_key(pbKeyIn, cbitKey, &key) == 0, COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION(AES_wrap_key(&key, nullptr, pbOut, pbContent, cbContent),
		COSE_ERR_CRYPTO_FAIL);

	cnTmp = cn_cbor_data_create2(
		pbOut, (int)cbContent + 8, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
	pbOut = nullptr;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_encrypt.m_message, cnTmp,
						INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);
	cnTmp = nullptr;

	return true;

errorReturn:
	COSE_FREE(cnTmp, context);
	if (pbOut != nullptr) {
		COSE_FREE(pbOut, context);
	}
	return false;
}

void rand_bytes(byte *pb, size_t cb)
{
	RAND_bytes(pb, (int)cb);
}

/*!
 *
 * @param[in] pRecipent	Pointer to the message object
 * @param[in] ppKeyPrivate	Address of key with private portion
 * @param[in] pKeyPublic	Address of the key w/o a private portion
 * @param[in/out] ppbSecret	pointer to buffer to hold the computed secret
 * @param[in/out] pcbSecret	size of the computed secret
 * @param[in] context		cbor allocation context structure
 * @param[out] perr			location to return error information
 * @returns		success of the function
 */

bool ECDH_ComputeSecret(COSE *pRecipient,
	COSE_KEY **ppKeyPrivate,
	COSE_KEY *pKeyPublic,
	byte **ppbSecret,
	size_t *pcbSecret,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	EVP_PKEY *evpPublic = nullptr;
	EVP_PKEY *evpPrivate = nullptr;
	EVP_PKEY_CTX *ctx = nullptr;

	if (false) {
	errorReturn:
		if (ctx != nullptr) {
			EVP_PKEY_CTX_free(ctx);
		}
		if (evpPublic != nullptr) {
			EVP_PKEY_free(evpPublic);
		}
		return false;
	}

	evpPublic = EVP_FromKey(pKeyPublic, CBOR_CONTEXT_PARAM_COMMA perr);
	if (evpPublic == nullptr) {
		goto errorReturn;
	}

	bool fCompressPoints = true;

	if (*ppKeyPrivate == nullptr) {
		// Generate an ephemeral key for the key agreement.

		int type = EVP_PKEY_base_id(evpPublic);
		cn_cbor *pCompress = _COSE_map_get_int(
			pRecipient, COSE_Header_UseCompressedECDH, COSE_DONT_SEND, perr);
		if (pCompress == nullptr) {
			fCompressPoints = true;
		}
		else {
			fCompressPoints = (pCompress->type == CN_CBOR_TRUE);
		}

		switch (type) {
			case EVP_PKEY_EC: {
				EC_KEY *peckeyPrivate = EC_KEY_new();
				EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);
				EC_KEY_set_group(
					peckeyPrivate, EC_KEY_get0_group(peckeyPublic));
				CHECK_CONDITION(EC_KEY_generate_key(peckeyPrivate) == 1,
					COSE_ERR_CRYPTO_FAIL);
				evpPrivate = EVP_PKEY_new();
				EVP_PKEY_set1_EC_KEY(evpPrivate, peckeyPrivate);
			} break;

			case EVP_PKEY_X25519:
			case EVP_PKEY_X448: {
				EVP_PKEY_CTX *ctx2 = EVP_PKEY_CTX_new_id(type, nullptr);
				CHECK_CONDITION(ctx2 != nullptr, COSE_ERR_OUT_OF_MEMORY);
				// CHECK_CONDITION(
				//	EVP_PKEY_paramgen_init(ctx2) == 1, COSE_ERR_CRYPTO_FAIL);
				CHECK_CONDITION(
					EVP_PKEY_keygen_init(ctx2) == 1, COSE_ERR_CRYPTO_FAIL);
				CHECK_CONDITION(
					EVP_PKEY_keygen(ctx2, &evpPrivate), COSE_ERR_CRYPTO_FAIL);
			} break;

			default:
				FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
		}

		cn_cbor *pcborPrivate = EVP_ToCBOR(
			evpPrivate, fCompressPoints, CBOR_CONTEXT_PARAM_COMMA perr);
		if (pcborPrivate == nullptr) {
			goto errorReturn;
		}
		COSE_KEY *pPrivateKey = (COSE_KEY *)COSE_KEY_FromEVP(
			evpPrivate, pcborPrivate, CBOR_CONTEXT_PARAM_COMMA perr);
		if (pPrivateKey == nullptr) {
			CN_CBOR_FREE(pcborPrivate, context);
			goto errorReturn;
		}
		*ppKeyPrivate = pPrivateKey;
	}
	else {
		//  Use the passed in sender key
		evpPrivate = EVP_FromKey(*ppKeyPrivate, CBOR_CONTEXT_PARAM_COMMA perr);
		if (evpPrivate == nullptr) {
			goto errorReturn;
		}
	}

	ctx = EVP_PKEY_CTX_new(evpPrivate, nullptr);
	CHECK_CONDITION(ctx != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(EVP_PKEY_derive_init(ctx) > 0, COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		EVP_PKEY_derive_set_peer(ctx, evpPublic) > 0, COSE_ERR_CRYPTO_FAIL);
	size_t skeylen;
	CHECK_CONDITION(
		EVP_PKEY_derive(ctx, nullptr, &skeylen) > 0, COSE_ERR_CRYPTO_FAIL);
	byte *skey = static_cast<byte *>(COSE_CALLOC(skeylen, 1, context));
	CHECK_CONDITION(skey != nullptr, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(
		EVP_PKEY_derive(ctx, skey, &skeylen) > 0, COSE_ERR_CRYPTO_FAIL);

	if (ctx != nullptr) {
		EVP_PKEY_CTX_free(ctx);
	}

	*ppbSecret = skey;
	*pcbSecret = skeylen;

	return true;
}

#endif	// COSE_C_USE_OPENSSL
