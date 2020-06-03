#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "cose_crypto.h"

#include <assert.h>
#ifndef __MBED__
#include <memory.h>
#endif
#include <stdlib.h>

#ifdef COSE_C_USE_MBEDTLS

#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/hkdf.h"

static bool FUseCompressed = true;

#ifdef INCLUDE_AES_CCM
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
	mbedtls_ccm_context ctx;
	int cbOut = 0;
	byte *rgbOut = nullptr;
	size_t NSize = 15 - (LSize / 8);
	byte rgbIV[15] = {0};
	const cn_cbor *pIV = nullptr;
	mbedtls_cipher_id_t cipher;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	mbedtls_ccm_init(&ctx);

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
		mbedtls_ccm_free(&ctx);
		return false;
	}
	CHECK_CONDITION(pIV->length == NSize, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbIV, pIV->v.str, pIV->length);

	//  Setup and run the mbedTLS code
	cipher = MBEDTLS_CIPHER_ID_AES;

	CHECK_CONDITION(!mbedtls_ccm_setkey(&ctx, cipher, pbKey, cbKey * 8),
		COSE_ERR_CRYPTO_FAIL);
	TSize /= 8;	 // Comes in in bits not bytes.

	cbOut = (int)cbCrypto - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		!mbedtls_ccm_auth_decrypt(&ctx, cbOut, rgbIV, NSize, pbAuthData,
			cbAuthData, pbCrypto, rgbOut, &pbCrypto[cbOut], TSize),
		COSE_ERR_CRYPTO_FAIL);

	mbedtls_ccm_free(&ctx);
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
	mbedtls_ccm_context ctx;
	int cbOut;
	byte *rgbOut = nullptr;
	size_t NSize = 15 - (LSize / 8);
	const cn_cbor *cbor_iv = nullptr;
	cn_cbor *cbor_iv_t = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
	cn_cbor *cnTmp = nullptr;
	mbedtls_cipher_id_t cipher;
	byte rgbIV[16];
	byte *pbIV = nullptr;
	cn_cbor_errback cbor_error;

	mbedtls_ccm_init(&ctx);

	cipher = MBEDTLS_CIPHER_ID_AES;

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

	//  Setup and run the mbedTLS code

	// cbKey comes in bytes not bits
	CHECK_CONDITION(!mbedtls_ccm_setkey(&ctx, cipher, pbKey, cbKey * 8),
		COSE_ERR_CRYPTO_FAIL);

	TSize /= 8;	 // Comes in in bits not bytes.

	cbOut = pcose->cbContent;  // M00BUG - This is a missing call?
	rgbOut = (byte *)COSE_CALLOC(cbOut + TSize, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(!mbedtls_ccm_encrypt_and_tag(&ctx, pcose->cbContent, rgbIV,
						NSize, pbAuthData, cbAuthData, pcose->pbContent, rgbOut,
						&rgbOut[pcose->cbContent], TSize),
		COSE_ERR_CRYPTO_FAIL);

	cnTmp = cn_cbor_data_create2(rgbOut, (int)pcose->cbContent + TSize, 0,
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
	rgbOut = nullptr;

	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);
	cnTmp = nullptr;

	mbedtls_ccm_free(&ctx);

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
	mbedtls_ccm_free(&ctx);
	return false;
}
#endif

#ifdef USE_AES_GCM
bool AES_GCM_Decrypt(COSE_Enveloped *pcose,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbCrypto,
	size_t cbCrypto,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	mbedtls_gcm_context ctx;
	int cbOut;
	byte *rgbOut = nullptr;
	byte rgbIV[15] = {0};
	const cn_cbor *pIV = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
	int TSize = 128 / 8;

	// Make it first so we can clean it up
	mbedtls_gcm_init(&ctx);

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
		mbedtls_gcm_free(&ctx);
		return false;
	}

	CHECK_CONDITION(pIV->length == 96 / 8, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbIV, pIV->v.str, pIV->length);

	//  Setup and run the OpenSSL code

	switch (cbKey) {
		case 128 / 8:
		case 192 / 8:
		case 256 / 8:
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	//  Do the setup for OpenSSL

	CHECK_CONDITION0(
		mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, pbKey, cbKey * 8),
		COSE_ERR_CRYPTO_FAIL);

	//

	cbOut = (int)cbCrypto - TSize;
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	//  Process content

	byte tag[128 / 8];
	CHECK_CONDITION0(
		mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, cbOut, rgbIV,
			96 / 8, pbAuthData, cbAuthData, pbCrypto, rgbOut, TSize, tag),
		COSE_ERR_CRYPTO_FAIL);

	//  CHECK TAG HERE
	bool f = false;
	const byte *pb = pbCrypto + cbOut;
	for (int i = 0; i < TSize; i++) {
		f |= (pb[i] != tag[i]);
	}
	CHECK_CONDITION(!f, COSE_ERR_CRYPTO_FAIL);

	mbedtls_gcm_free(&ctx);

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
	mbedtls_gcm_context ctx;
	byte *rgbOut = nullptr;
	byte rgbIV[16] = {0};
	byte *pbIV = nullptr;
	const cn_cbor *cbor_iv = nullptr;
	cn_cbor *cbor_iv_t = nullptr;
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
			COSE_FREE(cbor_iv_t, context);
		}
		if (rgbOut != nullptr) {
			COSE_FREE(rgbOut, context);
		}
		mbedtls_gcm_free(&ctx);
		return false;
	}

	// Make it first so we can clean it up
	mbedtls_gcm_init(&ctx);

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
		case 192:
		case 256:
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	//  Setup and run the OpenSSL code

	CHECK_CONDITION0(
		mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, pbKey, cbKey * 8),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION0(mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, rgbIV,
						 96 / 8, pbAuthData, cbAuthData),
		COSE_ERR_CRYPTO_FAIL);

	rgbOut = (byte *)COSE_CALLOC(pcose->cbContent + 128 / 8, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION0(
		mbedtls_gcm_update(&ctx, pcose->cbContent, pcose->pbContent, rgbOut),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION0(
		mbedtls_gcm_finish(&ctx, &rgbOut[pcose->cbContent], 128 / 8),
		COSE_ERR_CRYPTO_FAIL);

	cn_cbor *cnTmp = cn_cbor_data_create2(rgbOut,
		(int)pcose->cbContent + 128 / 8, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
	rgbOut = nullptr;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	mbedtls_gcm_free(&ctx);

	if (pbIV != nullptr) {
		COSE_FREE(pbIV, context);
	}
	return true;
}
#endif

#if defined(USE_HKDF_SHA2)
bool HKDF_Extract(COSE *pcose,
	const byte *pbKey,
	size_t cbKey,
	size_t cbitDigest,
	byte *rgbDigest,
	size_t *pcbDigest,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	const mbedtls_md_info_t *pmd = nullptr;
	mbedtls_md_type_t mdType;

	int cbSalt = 0;
	cn_cbor *cnSalt = nullptr;
	unsigned int cbDigest;

	if (0) {
	errorReturn:
		return false;
	}

	switch (cbitDigest) {
		case 256:
			mdType = MBEDTLS_MD_SHA256;
			cbDigest = 256 / 8;
			break;
		case 384:
			mdType = MBEDTLS_MD_SHA384;
			cbDigest = 384 / 8;
			break;
		case 512:
			mdType = MBEDTLS_MD_SHA512;
			cbDigest = 512 / 8;
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	pmd = mbedtls_md_info_from_type(mdType);
	if (pmd == nullptr) {
		goto errorReturn;
	}

	cbSalt = 0;
	const byte *pbSalt = nullptr;

	cnSalt = _COSE_map_get_int(pcose, COSE_Header_HKDF_salt, COSE_BOTH, perr);

	if (cnSalt != nullptr) {
		pbSalt = cnSalt->v.bytes;
		cbSalt = (int)cnSalt->length;
	}

	CHECK_CONDITION0(
		mbedtls_hkdf_extract(pmd, pbSalt, cbSalt, pbKey, cbKey, rgbDigest),
		COSE_ERR_CRYPTO_FAIL);

	*pcbDigest = cbDigest;

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
	UNUSED(pcose);
	mbedtls_md_type_t mdType;
	const mbedtls_md_info_t *pmd = nullptr;

	unsigned int cbDigest = 0;

	if (0) {
	errorReturn:
		return false;
	}

	switch (cbitDigest) {
		case 256:
			mdType = MBEDTLS_MD_SHA256;
			cbDigest = 256 / 8;
			break;
		case 384:
			mdType = MBEDTLS_MD_SHA384;
			cbDigest = 384 / 8;
			break;
		case 512:
			mdType = MBEDTLS_MD_SHA512;
			cbDigest = 512 / 8;
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	pmd = mbedtls_md_info_from_type(mdType);
	if (pmd == nullptr) {
		goto errorReturn;
	}

	if (mbedtls_hkdf_expand(
			pmd, pbPRK, cbPRK, pbInfo, cbInfo, pbOutput, cbOutput) != 0) {
		goto errorReturn;
	}

	return true;
}
#endif

#ifdef USE_HMAC
bool HMAC_Create(COSE_MacMessage *pcose,
	int HSize,
	int TSize,
	const byte *pbKey,
	size_t cbKey,
	const byte *pbAuthData,
	size_t cbAuthData,
	cose_errback *perr)
{
	byte *rgbOut = nullptr;
	//	unsigned int cbOut;
	mbedtls_md_context_t contx;
	const char *md_name;
	const struct mbedtls_md_info_t *info;
	cn_cbor *cbor = nullptr;

#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	switch (HSize) {
		case 256:
			md_name = "SHA256";
			break;
		case 384:
			md_name = "SHA384";
			break;
		case 512:
			md_name = "SHA512";
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	if (0) {
	errorReturn:
		if (cbor != nullptr) {
			COSE_FREE(cbor, context);
		}
		COSE_FREE(rgbOut, context);
		mbedtls_md_free(&contx);
		return false;
	}

	mbedtls_md_init(&contx);
	info = mbedtls_md_info_from_string(md_name);
	mbedtls_md_setup(&contx, info, 1);

	rgbOut = (byte *)COSE_CALLOC(mbedtls_md_get_size(info), 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		!(mbedtls_md_hmac_starts(&contx, pbKey, cbKey)), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(!(mbedtls_md_hmac_update(&contx, pbAuthData, cbAuthData)),
		COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		!(mbedtls_md_hmac_finish(&contx, rgbOut)), COSE_ERR_CRYPTO_FAIL);

	cbor = cn_cbor_data_create2(
		rgbOut, TSize / 8, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cbor != nullptr, COSE_ERR_OUT_OF_MEMORY);
	rgbOut = nullptr;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cbor, INDEX_MAC_TAG,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	mbedtls_md_free(&contx);
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
	mbedtls_md_context_t contx;
	const char *md_name;
	const struct mbedtls_md_info_t *info;
	byte *rgbOut = nullptr;
	unsigned int cbOut;
	bool f = false;
	unsigned int i;

#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

	if (false) {
	errorReturn:
		if (rgbOut != nullptr) {
			COSE_FREE(rgbOut, context);
		}
		mbedtls_md_free(&contx);
		return false;
	}

	switch (HSize) {
		case 256:
			md_name = "SHA256";
			break;
		case 384:
			md_name = "SHA384";
			break;
		case 512:
			md_name = "SHA512";
			break;
		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	mbedtls_md_init(&contx);
	info = mbedtls_md_info_from_string(md_name);
	mbedtls_md_setup(&contx, info, 1);

	cbOut = mbedtls_md_get_size(info);
	rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
	CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		!(mbedtls_md_hmac_starts(&contx, pbKey, cbKey)), COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(!(mbedtls_md_hmac_update(&contx, pbAuthData, cbAuthData)),
		COSE_ERR_CRYPTO_FAIL);
	CHECK_CONDITION(
		!(mbedtls_md_hmac_finish(&contx, rgbOut)), COSE_ERR_CRYPTO_FAIL);

	cn_cbor *cn = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_TAG);
	CHECK_CONDITION(cn != nullptr, COSE_ERR_CBOR);

	if (cn->length > (int)cbOut) {
		return false;
	}
	for (i = 0; i < (unsigned int)TSize / 8; i++) {
		f |= (cn->v.bytes[i] != rgbOut[i]);
	}

	COSE_FREE(rgbOut, context);
	mbedtls_md_free(&contx);
	return !f;
}
#endif

#define COSE_Key_EC_Curve -1
#define COSE_Key_EC_X -2
#define COSE_Key_EC_Y -3
#define COSE_Key_EC_d -4

mbedtls_ecp_keypair *ECKey_From(COSE_KEY *pKey,
	mbedtls_ecp_keypair *keypair,
	cose_errback *perr)
{
	if (pKey->m_mbedtls_keypair != nullptr) {
		return pKey->m_mbedtls_keypair;
	}

	byte rgbKey[MBEDTLS_ECP_MAX_PT_LEN];
	int cbKey = 0;
	int cbGroup = 0;
	const cn_cbor *p;
	mbedtls_ecp_group_id groupId;

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_Type);
	CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);
	if (p->type == CN_CBOR_UINT) {
		CHECK_CONDITION(
			p->v.uint == COSE_Key_Type_EC2, COSE_ERR_INVALID_PARAMETER);
	}
	else {
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_Curve);
	CHECK_CONDITION((p != nullptr) && (p->type == CN_CBOR_UINT),
		COSE_ERR_INVALID_PARAMETER);

	switch (p->v.uint) {
		case 1:	 // P-256
			groupId = MBEDTLS_ECP_DP_SECP256R1;
			break;

		case 2:	 // P-384
			groupId = MBEDTLS_ECP_DP_SECP384R1;
			break;

		case 3:	 // P-521
			groupId = MBEDTLS_ECP_DP_SECP521R1;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
	CHECK_CONDITION(mbedtls_ecp_group_load(&keypair->grp, groupId) == 0,
		COSE_ERR_INVALID_PARAMETER);
	cbGroup = (int)(keypair->grp.nbits + 7) / 8;

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_X);
	CHECK_CONDITION((p != nullptr) && (p->type == CN_CBOR_BYTES),
		COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(p->length == cbGroup, COSE_ERR_INVALID_PARAMETER);
	memcpy(rgbKey + 1, p->v.str, p->length);

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_Y);
	CHECK_CONDITION((p != nullptr), COSE_ERR_INVALID_PARAMETER);
	if (p->type == CN_CBOR_BYTES) {
		rgbKey[0] = 0x04;
		cbKey = cbGroup * 2 + 1;
		CHECK_CONDITION(p->length == cbGroup, COSE_ERR_INVALID_PARAMETER);
		memcpy(rgbKey + p->length + 1, p->v.str, p->length);
	}
	else if (p->type == CN_CBOR_TRUE) {
		perr->err = COSE_ERR_NO_COMPRESSED_POINTS;
		goto errorReturn;
		/*
		cbKey = cbGroup + 1;
		rgbKey[0] = 0x03;
		*/
	}
	else if (p->type == CN_CBOR_FALSE) {
		perr->err = COSE_ERR_NO_COMPRESSED_POINTS;
		goto errorReturn;
		/*
		cbKey = cbGroup + 1;
		rgbKey[0] = 0x02;
		*/
	}
	else {
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	CHECK_CONDITION(mbedtls_ecp_point_read_binary(
						&keypair->grp, &keypair->Q, rgbKey, cbKey) == 0,
		COSE_ERR_INVALID_PARAMETER);

	p = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC_d);
	if (p != nullptr) {
		CHECK_CONDITION(p->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(
			mbedtls_mpi_read_binary(&keypair->d, p->v.bytes, p->length) == 0,
			COSE_ERR_CRYPTO_FAIL);
	}
	return keypair;

errorReturn:
	return nullptr;
}

bool ECDSA_Sign(COSE *pSigner,
	int index,
	COSE_KEY *pKey,
	int cbitDigest,
	const byte *rgbToSign,
	size_t cbToSign,
	cose_errback *perr)
{
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
	byte rgbDigest[MBEDTLS_MD_MAX_SIZE];
	uint8_t *pbSig = nullptr;
	cn_cbor_errback cbor_error;
	int cbR;
	mbedtls_md_type_t mdType;
	const mbedtls_md_info_t *pmdInfo;
	mbedtls_ecp_keypair keypair;
	mbedtls_ecp_keypair *useKey = nullptr;
	mbedtls_mpi r;
	mbedtls_mpi s;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_allocContext;
#endif
	cn_cbor *p = nullptr;
	bool result = false;

	mbedtls_ecp_keypair_init(&keypair);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	useKey = ECKey_From(pKey, &keypair, perr);
	if (useKey == nullptr) {
		goto errorReturn;
	}

	CHECK_CONDITION(useKey->d.n != 0, COSE_ERR_INVALID_PARAMETER);

	switch (cbitDigest) {
		case 256:
			mdType = MBEDTLS_MD_SHA256;
			break;

		case 384:
			mdType = MBEDTLS_MD_SHA384;
			break;

		case 512:
			mdType = MBEDTLS_MD_SHA512;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
	pmdInfo = mbedtls_md_info_from_type(mdType);
	CHECK_CONDITION(pmdInfo != nullptr, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(mbedtls_md(pmdInfo, rgbToSign, cbToSign, rgbDigest) == 0,
		COSE_ERR_INVALID_PARAMETER);

	CHECK_CONDITION(mbedtls_ecdsa_sign_det(&useKey->grp, &r, &s, &useKey->d,
						rgbDigest, mbedtls_md_get_size(pmdInfo), mdType) == 0,
		COSE_ERR_CRYPTO_FAIL);

	cbR = (useKey->grp.nbits + 7) / 8;

	pbSig = (byte *)COSE_CALLOC(cbR, 2, context);
	CHECK_CONDITION(pbSig != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(
		mbedtls_mpi_write_binary(&r, pbSig, cbR) == 0, COSE_ERR_INTERNAL);
	CHECK_CONDITION(
		mbedtls_mpi_write_binary(&s, pbSig + cbR, cbR) == 0, COSE_ERR_INTERNAL);

	p = cn_cbor_data_create(
		pbSig, cbR * 2, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(p != nullptr, cbor_error);

	CHECK_CONDITION(_COSE_array_replace(
						pSigner, p, index, CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);

	p = nullptr;
	pbSig = nullptr;
	result = true;

errorReturn:
	cn_cbor_free(p CBOR_CONTEXT_PARAM);
	COSE_FREE(pbSig, context);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecp_keypair_free(&keypair);
	return result;
#else
	return false;
#endif
}

bool ECDSA_Verify(COSE *pSigner,
	int index,
	COSE_KEY *pKey,
	int cbitDigest,
	const byte *rgbToSign,
	size_t cbToSign,
	cose_errback *perr)
{
	mbedtls_ecp_keypair keypair;
	mbedtls_ecp_keypair *useKey = nullptr;
	mbedtls_mpi r;
	mbedtls_mpi s;
	mbedtls_md_type_t mdType;
	const mbedtls_md_info_t *pmdInfo;
	byte rgbDigest[MBEDTLS_MD_MAX_SIZE];
	cn_cbor *pSig;
	bool result = false;

	mbedtls_ecp_keypair_init(&keypair);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	useKey = ECKey_From(pKey, &keypair, perr);
	if (useKey == nullptr) {
		goto errorReturn;
	}

	switch (cbitDigest) {
		case 256:
			mdType = MBEDTLS_MD_SHA256;
			break;

		case 384:
			mdType = MBEDTLS_MD_SHA384;
			break;

		case 512:
			mdType = MBEDTLS_MD_SHA512;
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}
	pmdInfo = mbedtls_md_info_from_type(mdType);
	CHECK_CONDITION(pmdInfo != nullptr, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(mbedtls_md(pmdInfo, rgbToSign, cbToSign, rgbDigest) == 0,
		COSE_ERR_INVALID_PARAMETER);

	pSig = _COSE_arrayget_int(pSigner, index);
	CHECK_CONDITION((pSig != nullptr) && (pSig->type == CN_CBOR_BYTES),
		COSE_ERR_INVALID_PARAMETER);

	CHECK_CONDITION(
		mbedtls_mpi_read_binary(&r, pSig->v.bytes, pSig->length / 2) == 0,
		COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(
		mbedtls_mpi_read_binary(
			&s, pSig->v.bytes + pSig->length / 2, pSig->length / 2) == 0,
		COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(mbedtls_ecdsa_verify(&useKey->grp, rgbDigest,
						mbedtls_md_get_size(pmdInfo), &useKey->Q, &r, &s) == 0,
		COSE_ERR_CRYPTO_FAIL);

	result = true;

errorReturn:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecp_keypair_free(&keypair);
	return result;
}

#if defined(MBEDTLS_NIST_KW_C)
bool AES_KW_Decrypt(COSE_Enveloped *pcose,
	const byte *pbKeyIn,
	size_t cbitKey,
	const byte *pbCipherText,
	size_t cbCipherText,
	byte *pbKeyOut,
	int *pcbKeyOut,
	cose_errback *perr)
{
	mbedtls_nist_kw_context ctx;
	size_t cbKeyOut = 0;

	mbedtls_nist_kw_init(&ctx);

	CHECK_CONDITION0(mbedtls_nist_kw_setkey(
						 &ctx, MBEDTLS_CIPHER_ID_AES, pbKeyIn, cbitKey, FALSE),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION0(
		mbedtls_nist_kw_unwrap(&ctx, MBEDTLS_KW_MODE_KW, pbCipherText,
			cbCipherText, pbKeyOut, &cbKeyOut, cbCipherText - 8),
		COSE_ERR_CRYPTO_FAIL);

	*pcbKeyOut = (int)cbKeyOut;
	mbedtls_nist_kw_free(&ctx);
	return true;

errorReturn:
	mbedtls_nist_kw_free(&ctx);
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
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_encrypt.m_message.m_allocContext;
#endif
	cn_cbor *cnTmp = nullptr;
	mbedtls_nist_kw_context ctx;
	size_t cbOut;

	mbedtls_nist_kw_init(&ctx);

	pbOut = COSE_CALLOC(cbContent + 8, 1, context);
	CHECK_CONDITION(pbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION0(mbedtls_nist_kw_setkey(
						 &ctx, MBEDTLS_CIPHER_ID_AES, pbKeyIn, cbitKey, TRUE),
		COSE_ERR_CRYPTO_FAIL);

	CHECK_CONDITION0(mbedtls_nist_kw_wrap(&ctx, MBEDTLS_KW_MODE_KW, pbContent,
						 cbContent, pbOut, &cbOut, cbContent + 8),
		COSE_ERR_CRYPTO_FAIL);

	cnTmp = cn_cbor_data_create(
		pbOut, (int)cbContent + 8, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
	pbOut = nullptr;
	CHECK_CONDITION(_COSE_array_replace(&pcose->m_encrypt.m_message, cnTmp,
						INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_CBOR);
	cnTmp = nullptr;

	mbedtls_nist_kw_free(&ctx);
	return true;

errorReturn:
	COSE_FREE(cnTmp, context);
	if (pbOut != nullptr) {
		COSE_FREE(pbOut, context);
	}
	mbedtls_nist_kw_free(&ctx);
	return false;
}
#endif

/*
//#include <stdio.h> //TODO
void rand_bytes(byte * pb, size_t cb){
// https://tls.mbed.org/kb/how-to/add-a-random-generator
		//init random
	   mbedtls_ctr_drbg_context ctr_drbg;
		  char *personalization = "my_app_specific_string";

		ret = mbedtls_ctr_drbg_init( &ctr_drbg, mbedtls_entropy_func, &entropy,
										 (const unsigned char *)
personalization, strlen( personalization ) );

		if(ret != 0) {
			//printf TODO
		}

		mbedtls_ctr_drbg_random(&ctx,pb, cb);

	mbedtls_ctr_drbg_free(&ctx);
		printf("rand byute done\n");
}*/
// TODO HOW TO GENERATE GOOD RANDOM BYTES
#if 0
static const unsigned char entropy_source_pr[96] =
   { 0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16,
     0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02,
     0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b,
     0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb,
     0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9,
     0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95,
     0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63,
     0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3,
     0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31,
     0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4,
     0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56,
     0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68 };
#endif

static const unsigned char nonce_pers_pr[16] = {0xd2, 0x54, 0xfc, 0xff, 0x02,
	0x1e, 0x69, 0xd2, 0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c};

/*
static size_t test_offset;
static int ctr_drbg_self_test_entropy( void *data, unsigned char *buf, size_t
len ) { const unsigned char *p = data; memcpy( buf, p + test_offset, len );
	test_offset += len;
	return( 0 );
 }
*/

mbedtls_ctr_drbg_context ctxRandom;
int ctx_setup = 0;
mbedtls_entropy_context entropy;

void rand_bytes(byte *pb, size_t cb)
{
	// unsigned char buf[16];

	if (!ctx_setup) {
		mbedtls_entropy_init(&entropy);

		mbedtls_ctr_drbg_init(&ctxRandom);

		mbedtls_ctr_drbg_seed_entropy_len(&ctxRandom, mbedtls_entropy_func,
			(void *)&entropy, nonce_pers_pr, 16, 32);

		ctx_setup = 1;
	}

	// mbedtls_ctr_drbg_set_prediction_resistance( &ctx, MBEDTLS_CTR_DRBG_PR_ON
	// );

	mbedtls_ctr_drbg_random(&ctxRandom, pb, cb);
	// mbedtls_ctr_drbg_random( &ctx, buf, MBEDTLS_CTR_DRBG_BLOCKSIZE );
	// memcmp( buf, result_pr, MBEDTLS_CTR_DRBG_BLOCKSIZE ) );

	// mbedtls_ctr_drbg_free( &ctx );
}

int rand_bytes2(void *pv, unsigned char *pb, size_t cb)
{
	UNUSED(pv);
	rand_bytes(pb, cb);
	return 0;
}

// END OF TODO RANDOM BYTES

#if USE_ECDH
/*!
 *
 * @param[in] pRecipient	Pointer to the message object
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
	UNUSED(pRecipient);

	int cbGroup = 0;
	int cbsecret = 0;
	byte *pbsecret = nullptr;
	bool fRet = false;
	mbedtls_ecp_group_id groupId;
	mbedtls_ecp_keypair keypair;
	mbedtls_ecdh_context ctx;
	mbedtls_mpi d;
	cn_cbor *p = nullptr;
	mbedtls_mpi z;
	cn_cbor *pkey = nullptr;
	int cose_group = 0;
	mbedtls_ecp_group group = {MBEDTLS_ECP_DP_NONE};

	mbedtls_mpi_init(&z);
	mbedtls_ecdh_init(&ctx);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_keypair_init(&keypair);

	if (false) {
	errorReturn:
		if (pbsecret != nullptr) {
			COSE_FREE(pbsecret, context);
		}
		if (pkey != nullptr) {
			CN_CBOR_FREE(pkey, context);
		}
		if (p != nullptr) {
			CN_CBOR_FREE(p, context);
		}

		mbedtls_mpi_free(&d);
		mbedtls_mpi_free(&z);
		mbedtls_ecp_group_free(&group);
		mbedtls_ecp_keypair_free(&keypair);
		mbedtls_ecdh_free(&ctx);
		return fRet;
	}

	p = cn_cbor_mapget_int(pKeyPublic->m_cborKey, COSE_Key_EC_Curve);
	CHECK_CONDITION((p != nullptr) && (p->type == CN_CBOR_UINT),
		COSE_ERR_INVALID_PARAMETER);

	switch (p->v.uint) {
		case 1:	 // P-256
			groupId = MBEDTLS_ECP_DP_SECP256R1;
			cbGroup = 256 / 8;
			cose_group = 1;
			break;

		case 2:	 // P-384
			groupId = MBEDTLS_ECP_DP_SECP384R1;
			cbGroup = 384 / 12;
			cose_group = 2;
			break;

		case 3:	 // P-521
			groupId = MBEDTLS_ECP_DP_SECP521R1;
			cbGroup = (521 + 7) / 8;
			cose_group = 3;
			break;

		default:
			p = nullptr;
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	p = nullptr;

	CHECK_CONDITION0(
		mbedtls_ecp_group_load(&group, groupId), COSE_ERR_INVALID_PARAMETER);

	if (!ECKey_From(pKeyPublic, &keypair, perr)) {
		goto errorReturn;
	}

	if (*ppKeyPrivate == nullptr) {
		mbedtls_ecp_keypair privateKeyPair;
		mbedtls_ecp_keypair_init(&privateKeyPair);

		CHECK_CONDITION0(
			mbedtls_ecp_gen_key(groupId, &privateKeyPair, rand_bytes2, nullptr),
			COSE_ERR_CRYPTO_FAIL);
		CHECK_CONDITION0(
			mbedtls_mpi_copy(&d, &privateKeyPair.d), COSE_ERR_CRYPTO_FAIL);

		size_t olen = 0;
		byte buff[528 * 2 / 8 + 1];
		CHECK_CONDITION0(
			mbedtls_ecp_point_write_binary(&group, &privateKeyPair.Q,
				MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buff, sizeof(buff)),
			COSE_ERR_CRYPTO_FAIL);

		cn_cbor_errback cbor_error;
		int cbSize = (int)(olen - 1) / 2;

		pkey = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(pkey != nullptr, cbor_error);

		p = cn_cbor_int_create(
			cose_group, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_Curve, p,
								 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
			cbor_error);
		p = nullptr;

		pbsecret = (byte *)COSE_CALLOC(cbSize, 1, context);
		CHECK_CONDITION(pbsecret != nullptr, COSE_ERR_OUT_OF_MEMORY);
		memcpy(pbsecret, buff + 1, cbSize);

		p = cn_cbor_data_create2(
			pbsecret, (int)cbSize, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
		pbsecret = nullptr;
		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_X, p,
								 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
			cbor_error);
		p = nullptr;

		pbsecret = (byte *)COSE_CALLOC(cbSize, 1, context);
		CHECK_CONDITION(pbsecret != nullptr, COSE_ERR_OUT_OF_MEMORY);
		memcpy(pbsecret, buff + 1 + cbSize, cbSize);

		p = cn_cbor_data_create2(
			pbsecret, cbSize, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
		pbsecret = nullptr;
		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_EC_Y, p,
								 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
			cbor_error);
		p = nullptr;

		p = cn_cbor_int_create(
			COSE_Key_Type_EC2, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(p != nullptr, cbor_error);
		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pkey, COSE_Key_Type, p,
								 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
			cbor_error);
		p = nullptr;

		COSE_KEY *coseKey =
			(COSE_KEY *)COSE_KEY_FromCbor(pkey, CBOR_CONTEXT_PARAM_COMMA perr);
		if (coseKey == nullptr) {
			goto errorReturn;
		}

		*ppKeyPrivate = coseKey;
		pkey = nullptr;
	}
	else {
		p = cn_cbor_mapget_int((*ppKeyPrivate)->m_cborKey, COSE_Key_EC_d);
		CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);

		CHECK_CONDITION(p->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION0(mbedtls_mpi_read_binary(&d, p->v.bytes, p->length),
			COSE_ERR_CRYPTO_FAIL);
		p = nullptr;
	}

	CHECK_CONDITION0(mbedtls_ecdh_compute_shared(
						 &group, &z, &keypair.Q, &d, nullptr, nullptr),
		COSE_ERR_CRYPTO_FAIL);

	cbsecret = cbGroup;
	pbsecret = (byte *)COSE_CALLOC(cbsecret, 1, context);
	CHECK_CONDITION(pbsecret != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION0(
		mbedtls_mpi_write_binary(&z, pbsecret, cbsecret), COSE_ERR_CRYPTO_FAIL);

	*ppbSecret = pbsecret;
	*pcbSecret = cbsecret;
	pbsecret = nullptr;

	fRet = true;
	goto errorReturn;
}
#endif	// USE_ECDH
#endif	// COSE_C_USE_MBEDTLS
