/** \file SignerInfo.c
 * Contains implementation of the functions related to HCOSE_SIGNER handle
 * objects.
 */

#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "crypto.h"

#if INCLUDE_SIGN || INCLUDE_COUNTERSIGNATURE

#if INCLUDE_SIGN
COSE *SignerRoot = NULL;

bool IsValidSignerHandle(HCOSE_SIGNER h)
{
	COSE_SignerInfo *p = (COSE_SignerInfo *)h;
	return _COSE_IsInList(SignerRoot, (COSE *)p);
}
#endif

bool _COSE_SignerInfo_Release(COSE_SignerInfo *pSigner)
{
	//  Check ref counting
	if (pSigner->m_message.m_refCount > 1) {
		pSigner->m_message.m_refCount--;
		return true;
	}

	_COSE_Release(&pSigner->m_message);

	return true;
}

#if INCLUDE_SIGN
bool COSE_Signer_Free(HCOSE_SIGNER hSigner)
{
	COSE_SignerInfo *pSigner = (COSE_SignerInfo *)hSigner;
	bool fRet = false;

	if (!IsValidSignerHandle(hSigner)) {
		goto errorReturn;
	}

	if (pSigner->m_message.m_refCount > 1) {
		pSigner->m_message.m_refCount--;
		return true;
	}

	_COSE_SignerInfo_Release(pSigner);

	_COSE_RemoveFromList(&SignerRoot, &pSigner->m_message);

	COSE_FREE(pSigner, &pSigner->m_message.m_allocContext);

	fRet = true;
errorReturn:
	return fRet;
}

HCOSE_SIGNER COSE_Signer_Init(CBOR_CONTEXT_COMMA cose_errback *perror)
{
	COSE_SignerInfo *pobj =
		(COSE_SignerInfo *)COSE_CALLOC(1, sizeof(COSE_SignerInfo), context);
	if (pobj == NULL) {
		if (perror != NULL) {
			perror->err = COSE_ERR_OUT_OF_MEMORY;
		}
		return NULL;
	}

	if (!_COSE_SignerInfo_Init(COSE_INIT_FLAGS_NO_CBOR_TAG, pobj,
			COSE_recipient_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_SignerInfo_Release(pobj);
		COSE_FREE(pobj, context);
		return NULL;
	}

	_COSE_InsertInList(&SignerRoot, &pobj->m_message);
	return (HCOSE_SIGNER)pobj;
}
#endif

bool _COSE_SignerInfo_Init(COSE_INIT_FLAGS flags,
	COSE_SignerInfo *pobj,
	int msgType,
	CBOR_CONTEXT_COMMA cose_errback *errp)
{
	return _COSE_Init(
		flags, &pobj->m_message, msgType, CBOR_CONTEXT_PARAM_COMMA errp);
}

COSE_SignerInfo *_COSE_SignerInfo_Init_From_Object(cn_cbor *cbor,
	COSE_SignerInfo *pIn,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	COSE_SignerInfo *pSigner = pIn;

	if (pSigner == NULL) {
		pSigner =
			(COSE_SignerInfo *)COSE_CALLOC(1, sizeof(COSE_SignerInfo), context);
		CHECK_CONDITION(pSigner != NULL, COSE_ERR_OUT_OF_MEMORY);
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

	if (!_COSE_Init_From_Object(
			&pSigner->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

#if INCLUDE_SIGN
	if (pIn == NULL) {
		_COSE_InsertInList(&SignerRoot, &pSigner->m_message);
	}
#endif
	return pSigner;

errorReturn:
	if (pSigner != NULL && pIn == NULL) {
		_COSE_SignerInfo_Release(pSigner);
		COSE_FREE(pSigner, context);
	}
	return NULL;
}

static bool BuildToBeSigned(byte **ppbToSign,
	size_t *pcbToSign,
	const cn_cbor *pcborBody,
	const cn_cbor *pcborProtected,
	const cn_cbor *pcborProtectedSign,
	const byte *pbExternal,
	size_t cbExternal,
	const char *const contextString,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	cn_cbor *pArray = NULL;
	cn_cbor_errback cbor_error;
	size_t cbToSign;
	byte *pbToSign = NULL;
	bool f = false;
	cn_cbor *cn = NULL;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(pArray != NULL, cbor_error);

	cn = cn_cbor_string_create(
		contextString, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	if (pcborProtected->length == 1 && (pcborProtected->v.bytes[0] == 0xa0)) {
		cn =
			cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cn = cn_cbor_data_create(pcborProtected->v.bytes,
			(int)pcborProtected->length, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	if ((pcborProtectedSign->length == 1) &&
		(pcborProtectedSign->v.bytes[0] == 0xa0)) {
		cn =
			cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cn = cn_cbor_data_create(pcborProtectedSign->v.bytes,
			(int)pcborProtectedSign->length,
			CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(
		pbExternal, (int)cbExternal, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(pcborBody->v.bytes, (int)pcborBody->length,
		CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cbToSign = cn_cbor_encode_size(pArray);
	CHECK_CONDITION(cbToSign > 0, COSE_ERR_CBOR);
	pbToSign = (byte *)COSE_CALLOC(cbToSign, 1, context);
	CHECK_CONDITION(pbToSign != NULL, COSE_ERR_OUT_OF_MEMORY);
	const ssize_t writtenBits =
		cn_cbor_encoder_write(pbToSign, 0, cbToSign, pArray);
	CHECK_CONDITION(writtenBits >= 0, COSE_ERR_CBOR);
	CHECK_CONDITION((size_t)writtenBits == cbToSign, COSE_ERR_CBOR);

	*ppbToSign = pbToSign;
	*pcbToSign = cbToSign;
	pbToSign = NULL;
	f = true;

errorReturn:
	if (cn != NULL) {
		CN_CBOR_FREE(cn, context);
	}
	if (pArray != NULL) {
		CN_CBOR_FREE(pArray, context);
	}
	if (pbToSign != NULL) {
		COSE_FREE(pbToSign, context);
	}
	return f;
}

bool _COSE_Signer_sign(COSE_SignerInfo *pSigner,
	const cn_cbor *pcborBody,
	const cn_cbor *pcborProtected,
	const char *const contextString,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor *pcborProtectedSign = NULL;
	cn_cbor *pArray = NULL;
	cn_cbor *cnAlgorithm = NULL;
	size_t cbToSign;
	byte *pbToSign = NULL;
	int alg;
	bool fRet = false;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pArray != NULL, COSE_ERR_OUT_OF_MEMORY);

	cnAlgorithm = _COSE_map_get_int(
		&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cnAlgorithm == NULL) {
		goto errorReturn;
	}

	if (cnAlgorithm->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cnAlgorithm->type == CN_CBOR_UINT ||
							cnAlgorithm->type == CN_CBOR_INT),
			COSE_ERR_INVALID_PARAMETER);

		alg = (int)cnAlgorithm->v.sint;
	}

	pcborProtectedSign = _COSE_encode_protected(&pSigner->m_message, perr);
	if (pcborProtectedSign == NULL) {
		goto errorReturn;
	}

	if (!BuildToBeSigned(&pbToSign, &cbToSign, pcborBody, pcborProtected,
			pcborProtectedSign, pSigner->m_message.m_pbExternal,
			pSigner->m_message.m_cbExternal, contextString,
			CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	switch (alg) {
#ifdef USE_ECDSA_SHA_256
		case COSE_Algorithm_ECDSA_SHA_256:
			if (!ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, 256, pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDSA_SHA_384
		case COSE_Algorithm_ECDSA_SHA_384:
			if (!ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, 384, pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDSA_SHA_512
		case COSE_Algorithm_ECDSA_SHA_512:
			if (!ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, 512, pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_EDDSA
		case COSE_Algorithm_EdDSA:
			if (!EdDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}

#if INCLUDE_COUNTERSIGNATURE
	if (pSigner->m_message.m_counterSigners != NULL) {
		if (!_COSE_CounterSign_Sign(
				&pSigner->m_message, CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif

	fRet = true;

errorReturn:
	if (pArray != NULL) {
		COSE_FREE(pArray, context);
	}
	if (pbToSign != NULL) {
		COSE_FREE(pbToSign, context);
	}
	return fRet;
}

#if INCLUDE_SIGN
bool COSE_Signer_SetKey(HCOSE_SIGNER h, const cn_cbor *pKey, cose_errback *perr)
{
	COSE_SignerInfo *p;
	bool fRet = false;

	CHECK_CONDITION(IsValidSignerHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pKey != NULL, COSE_ERR_INVALID_PARAMETER);

	p = (COSE_SignerInfo *)h;
	p->m_pkey = pKey;

	fRet = true;
errorReturn:
	return fRet;
}

/*!
 * @brief Set the application external data for authentication
 *
 * Signer data objects support the authentication of external application
 * supplied data.  This function is provided to supply that data to the library.
 *
 * The external data is not copied, nor will be it freed when the handle is
 * released.
 *
 * @param hcose  Handle for the COSE MAC data object
 * @param pbEternalData  point to the external data
 * @param cbExternalData size of the external data
 * @param perr  location to return errors
 * @return result of the operation.
 */

bool COSE_Signer_SetExternal(HCOSE_SIGNER hcose,
	const byte *pbExternalData,
	size_t cbExternalData,
	cose_errback *perr)
{
	if (!IsValidSignerHandle(hcose)) {
		if (perr != NULL) {
			perr->err = COSE_ERR_INVALID_HANDLE;
		}
		return false;
	}

	return _COSE_SetExternal(&((COSE_SignerInfo *)hcose)->m_message,
		pbExternalData, cbExternalData, perr);
}
#endif

bool _COSE_Signer_validate(COSE_SignerInfo *pSigner,
	const cn_cbor *pcborBody,
	const cn_cbor *pcborProtected,
	const char *const contextString,
	cose_errback *perr)
{
	byte *pbToBeSigned = NULL;
	int alg = 0;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_message.m_allocContext;
#endif
	size_t cbToBeSigned;
	bool fRet = false;

	const cn_cbor *cn = _COSE_map_get_int(
		&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) {
		goto errorReturn;
	}

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT),
			COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.sint;
	}

	//  Build protected headers

	cn_cbor *cnProtected =
		_COSE_arrayget_int(&pSigner->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(
		(cnProtected != NULL) && (cnProtected->type == CN_CBOR_BYTES),
		COSE_ERR_INVALID_PARAMETER);

	//  Build authenticated data
	if (!BuildToBeSigned(&pbToBeSigned, &cbToBeSigned, pcborBody,
			pcborProtected, cnProtected, pSigner->m_message.m_pbExternal,
			pSigner->m_message.m_cbExternal, contextString,
			CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	cn_cbor *cnSignature =
		_COSE_arrayget_int(&pSigner->m_message, INDEX_SIGNATURE);
	CHECK_CONDITION(
		(cnSignature != NULL) && (cnSignature->type == CN_CBOR_BYTES),
		COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
#ifdef USE_ECDSA_SHA_256
		case COSE_Algorithm_ECDSA_SHA_256:
			if (!ECDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, 256, pbToBeSigned, cbToBeSigned, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDSA_SHA_384
		case COSE_Algorithm_ECDSA_SHA_384:
			if (!ECDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, 384, pbToBeSigned, cbToBeSigned, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDSA_SHA_512
		case COSE_Algorithm_ECDSA_SHA_512:
			if (!ECDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, 512, pbToBeSigned, cbToBeSigned, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_EDDSA
		case COSE_Algorithm_EdDSA:
			if (!EdDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE,
					pSigner->m_pkey, pbToBeSigned, cbToBeSigned, perr)) {
				goto errorReturn;
			}
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			break;
	}

	fRet = true;

errorReturn:
	if (pbToBeSigned != NULL) {
		COSE_FREE(pbToBeSigned, context);
	}

	return fRet;
}

#if INCLUDE_SIGN
cn_cbor *COSE_Signer_map_get_int(HCOSE_SIGNER h,
	int key,
	int flags,
	cose_errback *perr)
{
	if (!IsValidSignerHandle(h)) {
		if (perr != NULL) {
			perr->err = COSE_ERR_INVALID_HANDLE;
		}
		return NULL;
	}

	return _COSE_map_get_int((COSE *)h, key, flags, perr);
}

bool COSE_Signer_map_put_int(HCOSE_SIGNER h,
	int key,
	cn_cbor *value,
	int flags,
	cose_errback *perr)
{
	CHECK_CONDITION(IsValidSignerHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

	return _COSE_map_put(
		&((COSE_SignerInfo *)h)->m_message, key, value, flags, perr);

errorReturn:
	return false;
}
#endif
#endif
