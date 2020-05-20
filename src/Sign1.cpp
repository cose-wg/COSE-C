/** \file Sign1.c
 * Contains implementation of the functions related to HCOSE_SIGN handle
 * objects.
 */

#include <stdlib.h>

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "cose_crypto.h"

#if INCLUDE_SIGN1

bool _COSE_Signer1_sign(COSE_Sign1Message *pSigner,
	COSE_KEY *pKey,
	cose_errback *perr);
bool _COSE_Signer1_validate(COSE_Sign1Message *pSign,
	COSE_KEY *pKey,
	cose_errback *perr);

COSE *Sign1Root = nullptr;

/*! \private
 * @brief Test if a HCOSE_SIGN1 handle is valid
 *
 *  Internal function to test if a sign1 message handle is valid.
 *  This will start returning invalid results and cause the code to
 *  crash if handles are not released before the memory that underlies them
 *  is deallocated.  This is an issue of a block allocator is used since
 *  in that case it is common to allocate memory but never to de-allocate it
 *  and just do that in a single big block.
 *
 *  @param h handle to be validated
 *  @returns result of check
 */

bool IsValidSign1Handle(HCOSE_SIGN1 h)
{
	COSE_Sign1Message *p = (COSE_Sign1Message *)h;

	if (p == nullptr) {
		return false;
	}
	return _COSE_IsInList(Sign1Root, (COSE *)p);
}

HCOSE_SIGN1 COSE_Sign1_Init(COSE_INIT_FLAGS flags,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	if (false) {
	errorReturn:
		return nullptr;
	}

	CHECK_CONDITION(flags == COSE_INIT_FLAGS_NONE, COSE_ERR_INVALID_PARAMETER);
	COSE_Sign1Message *pobj =
		(COSE_Sign1Message *)COSE_CALLOC(1, sizeof(COSE_Sign1Message), context);
	if (pobj == nullptr) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_OUT_OF_MEMORY;
		}
		return nullptr;
	}

	if (!_COSE_Init(flags, &pobj->m_message, COSE_sign_object,
			CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Sign1_Release(pobj);
		COSE_FREE(pobj, context);
		return nullptr;
	}

	_COSE_InsertInList(&Sign1Root, &pobj->m_message);

	return (HCOSE_SIGN1)pobj;
}

HCOSE_SIGN1 _COSE_Sign1_Init_From_Object(cn_cbor *cbor,
	COSE_Sign1Message *pIn,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	COSE_Sign1Message *pobj = pIn;
	cose_errback error = {COSE_ERR_NONE};

	if (perr == nullptr) {
		perr = &error;
	}

	if (pobj == nullptr) {
		pobj = (COSE_Sign1Message *)COSE_CALLOC(
			1, sizeof(COSE_Sign1Message), context);
	}
	CHECK_CONDITION(pobj != nullptr, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init_From_Object(
			&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	if (pIn == nullptr) {
		_COSE_InsertInList(&Sign1Root, &pobj->m_message);
	}

	return (HCOSE_SIGN1)pobj;

errorReturn:
	if (pobj != nullptr) {
		pobj->m_message.m_ownMsg = false;
		_COSE_Sign1_Release(pobj);
		if (pIn == nullptr) {
			COSE_FREE(pobj, context);
		}
	}
	return nullptr;
}

bool COSE_Sign1_Free(HCOSE_SIGN1 h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context;
#endif
	COSE_Sign1Message *pMessage = (COSE_Sign1Message *)h;

	if (!IsValidSign1Handle(h)) {
		return false;
	}

	//  Check reference counting
	if (pMessage->m_message.m_refCount > 1) {
		pMessage->m_message.m_refCount--;
		return true;
	}

	_COSE_RemoveFromList(&Sign1Root, &pMessage->m_message);

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	_COSE_Sign1_Release(pMessage);

	COSE_FREE(pMessage, context);

	return true;
}

void _COSE_Sign1_Release(COSE_Sign1Message *p)
{
	_COSE_Release(&p->m_message);
}

bool COSE_Sign1_SetContent(HCOSE_SIGN1 h,
	const byte *rgb,
	size_t cb,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = nullptr;
#endif
	cn_cbor *p = nullptr;
	COSE_Sign1Message *pMessage = (COSE_Sign1Message *)h;
	bool fRet = false;

	CHECK_CONDITION(IsValidSign1Handle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(rgb != nullptr, COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	p = cn_cbor_data_create(rgb, (int)cb, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_CONDITION(p != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(_COSE_array_replace(&pMessage->m_message, p, INDEX_BODY,
						CBOR_CONTEXT_PARAM_COMMA nullptr),
		COSE_ERR_OUT_OF_MEMORY);
	p = nullptr;

	fRet = true;

errorReturn:
	if (p != nullptr) {
		CN_CBOR_FREE(p, context);
	}
	return fRet;
}

/*!
 * @brief Set the application external data for authentication
 *
 * Enveloped data objects support the authentication of external application
 * supplied data.  This function is provided to supply that data to the library.
 *
 * The external data is not copied, nor will be it freed when the handle is
 * released.
 *
 * @param hcose  Handle for the COSE Enveloped data object
 * @param pbEternalData  point to the external data
 * @param cbExternalData size of the external data
 * @param perr  location to return errors
 * @return result of the operation.
 */

bool COSE_Sign1_SetExternal(HCOSE_SIGN1 hcose,
	const byte *pbExternalData,
	size_t cbExternalData,
	cose_errback *perr)
{
	if (!IsValidSign1Handle(hcose)) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_INVALID_HANDLE;
		}
		return false;
	}

	return _COSE_SetExternal(&((COSE_Sign1Message *)hcose)->m_message,
		pbExternalData, cbExternalData, perr);
}

bool COSE_Sign1_Sign(HCOSE_SIGN1 h, const cn_cbor *pKey, cose_errback *perr)
{
	HCOSE_KEY cose = nullptr;
	bool fRet = false;

	if (false) {
	errorReturn:
		if (cose != nullptr) {
			//  Don't free the passed in key.
			((COSE_KEY *)cose)->m_cborKey = nullptr;
			COSE_KEY_Free(cose);
		}
		return fRet;
	}

	CHECK_CONDITION(pKey != nullptr, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(IsValidSign1Handle(h), COSE_ERR_INVALID_HANDLE);

#ifdef USE_CBOR_CONTEXT
	COSE_Sign1Message *pmessage = (COSE_Sign1Message *)h;
	cn_cbor_context *context = &pmessage->m_message.m_allocContext;
#endif

	cose = COSE_KEY_FromCbor((cn_cbor *)pKey, CBOR_CONTEXT_PARAM_COMMA perr);
	if (cose == nullptr) {
		goto errorReturn;
	}

	fRet = COSE_Sign1_Sign2(h, cose, perr);
	goto errorReturn;
}

bool COSE_Sign1_Sign2(HCOSE_SIGN1 h, HCOSE_KEY hKey, cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = nullptr;
#endif
	COSE_Sign1Message *pMessage = (COSE_Sign1Message *)h;
	const cn_cbor *pcborProtected;

	if (!IsValidSign1Handle(h)) {
		CHECK_CONDITION(false, COSE_ERR_INVALID_HANDLE);
	errorReturn:
		return false;
	}
	CHECK_CONDITION(IsValidKeyHandle(hKey), COSE_ERR_INVALID_HANDLE);

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	pcborProtected = _COSE_encode_protected(&pMessage->m_message, perr);
	if (pcborProtected == nullptr) {
		goto errorReturn;
	}

	if (!_COSE_Signer1_sign(pMessage, (COSE_KEY *)hKey, perr)) {
		goto errorReturn;
	}

#if INCLUDE_COUNTERSIGNATURE
	if (pMessage->m_message.m_counterSigners != nullptr) {
		if (!_COSE_CounterSign_Sign(
				&pMessage->m_message, CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif
#if INCLUDE_COUNTERSIGNATURE1
	if (pMessage->m_message.m_counterSign1 != NULL) {
		if (!_COSE_CounterSign1_Sign(
				&pMessage->m_message, CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif

	return true;
}

bool COSE_Sign1_validate2(HCOSE_SIGN1 hSign, HCOSE_KEY hKey, cose_errback *perr)
{
	bool f;
	COSE_KEY *pcose = nullptr;

	if (false) {
	errorReturn:
		if (pcose != nullptr) {
			COSE_KEY_Free((HCOSE_KEY)pcose);
		}
		return false;
	}

	CHECK_CONDITION(IsValidSign1Handle(hSign), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidKeyHandle(hKey), COSE_ERR_INVALID_HANDLE);

	COSE_Sign1Message *pSign = (COSE_Sign1Message *)hSign;

	const cn_cbor *cnContent =
		_COSE_arrayget_int(&pSign->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != nullptr && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor *cnProtected =
		_COSE_arrayget_int(&pSign->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(
		cnProtected != nullptr && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	pcose = (COSE_KEY *)hKey;

	f = _COSE_Signer1_validate(pSign, pcose, perr);

	return f;
}

bool COSE_Sign1_validate(HCOSE_SIGN1 hSign,
	const cn_cbor *pKey,
	cose_errback *perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidSign1Handle(hSign), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pKey != NULL, COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	COSE_Sign1Message *pSign = (COSE_Sign1Message *)hSign;

	cn_cbor_context *context = &pSign->m_message.m_allocContext;
#endif

	HCOSE_KEY hcose =
		COSE_KEY_FromCbor((cn_cbor *)pKey, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(pKey != NULL, COSE_ERR_OUT_OF_MEMORY);

	bool f = COSE_Sign1_validate2(hSign, hcose, perr);

	((COSE_KEY *)hcose)->m_cborKey = nullptr;
	COSE_KEY_Free(hcose);

	return f;
}

cn_cbor *COSE_Sign1_map_get_int(HCOSE_SIGN1 h,
	int key,
	int flags,
	cose_errback *perror)
{
	if (!IsValidSign1Handle(h)) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_INVALID_HANDLE;
		}
		return nullptr;
	}

	return _COSE_map_get_int(
		&((COSE_Sign1Message *)h)->m_message, key, flags, perror);
}

bool COSE_Sign1_map_put_int(HCOSE_SIGN1 h,
	int key,
	cn_cbor *value,
	int flags,
	cose_errback *perr)
{
	CHECK_CONDITION(IsValidSign1Handle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != nullptr, COSE_ERR_INVALID_PARAMETER);

	return _COSE_map_put(
		&((COSE_Sign1Message *)h)->m_message, key, value, flags, perr);

errorReturn:
	return false;
}

static bool CreateSign1AAD(COSE_Sign1Message *pMessage,
	byte **ppbToSign,
	size_t *pcbToSign,
	const char *szContext,
	cose_errback *perr)
{
	cn_cbor *pArray = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pMessage->m_message.m_allocContext;
#endif
	cn_cbor_errback cbor_error;
	cn_cbor *cn = nullptr;
	cn_cbor *cn2;
	size_t cbToSign;
	byte *pbToSign = nullptr;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(pArray != nullptr, cbor_error);

	cn =
		cn_cbor_string_create(szContext, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = nullptr;

	cn2 = _COSE_arrayget_int(&pMessage->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cn2 != nullptr, COSE_ERR_INVALID_PARAMETER);

	if ((cn2->length == 1) && (cn2->v.bytes[0] == 0xa0)) {
		cn = cn_cbor_data_create(
			nullptr, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cn = cn_cbor_data_create(cn2->v.bytes, (int)cn2->length,
			CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cn != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = nullptr;

	cn = cn_cbor_data_create(pMessage->m_message.m_pbExternal,
		(int)pMessage->m_message.m_cbExternal,
		CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = nullptr;

	cn2 = _COSE_arrayget_int(&pMessage->m_message, INDEX_BODY);
	cn = cn_cbor_data_create(
		cn2->v.bytes, (int)cn2->length, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = nullptr;

	cbToSign = cn_cbor_encode_size(pArray);
	CHECK_CONDITION(cbToSign > 0, COSE_ERR_CBOR);
	pbToSign = (byte *)COSE_CALLOC(cbToSign, 1, context);
	CHECK_CONDITION(pbToSign != nullptr, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(cn_cbor_encoder_write(pbToSign, 0, cbToSign, pArray) ==
						(ssize_t)cbToSign,
		COSE_ERR_CBOR);

	*ppbToSign = pbToSign;
	*pcbToSign = cbToSign;
	pbToSign = nullptr;

	if (cn != nullptr) {
		CN_CBOR_FREE(cn, context);
	}
	if (pArray != nullptr) {
		CN_CBOR_FREE(pArray, context);
	}
	return true;

errorReturn:
	if (pbToSign != nullptr) {
		COSE_FREE(pbToSign, context);
	}
	if (cn != nullptr) {
		CN_CBOR_FREE(cn, context);
	}
	if (pArray != nullptr) {
		CN_CBOR_FREE(pArray, context);
	}
	return false;
}

bool _COSE_Signer1_sign(COSE_Sign1Message *pSigner,
	COSE_KEY *pKey,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor *pcborBody2 = nullptr;
	cn_cbor *pcborProtected2 = nullptr;
	cn_cbor *pArray = nullptr;
	cn_cbor *cn = nullptr;
	size_t cbToSign;
	byte *pbToSign = nullptr;
	bool f;
	int alg;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (pArray == nullptr) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_OUT_OF_MEMORY;
		}
	errorReturn:
		if (pcborBody2 != nullptr) {
			CN_CBOR_FREE(pcborBody2, context);
		}
		if (pcborProtected2 != nullptr) {
			CN_CBOR_FREE(pcborProtected2, context);
		}
		if (pArray != nullptr) {
			COSE_FREE(pArray, context);
		}
		if (pbToSign != nullptr) {
			COSE_FREE(pbToSign, context);
		}
		return false;
	}

	cn = _COSE_map_get_int(
		&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == nullptr) {
		goto errorReturn;
	}

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT),
			COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}

	if (!CreateSign1AAD(pSigner, &pbToSign, &cbToSign, "Signature1", perr)) {
		goto errorReturn;
	}

	switch (alg) {
#ifdef USE_ECDSA_SHA_256
		case COSE_Algorithm_ECDSA_SHA_256:
			f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE + 1, pKey, 256,
				pbToSign, cbToSign, perr);
			break;
#endif

#ifdef USE_ECDSA_SHA_384
		case COSE_Algorithm_ECDSA_SHA_384:
			f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE + 1, pKey, 384,
				pbToSign, cbToSign, perr);
			break;
#endif

#ifdef USE_ECDSA_SHA_512
		case COSE_Algorithm_ECDSA_SHA_512:
			f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE + 1, pKey, 512,
				pbToSign, cbToSign, perr);
			break;
#endif

#ifdef USE_EDDSA
		case COSE_Algorithm_EdDSA:
			f = EdDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE + 1, pKey,
				pbToSign, cbToSign, perr);
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}

	COSE_FREE(pbToSign, context);
	CN_CBOR_FREE(pArray, context);

	return f;
}

bool _COSE_Signer1_validate(COSE_Sign1Message *pSign,
	COSE_KEY *pKey,
	cose_errback *perr)
{
	byte *pbToSign = nullptr;
	int alg;
	const cn_cbor *cn = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = nullptr;
#endif
	size_t cbToSign;
	bool fRet = false;

#ifdef USE_CBOR_CONTEXT
	context = &pSign->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(
		&pSign->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == nullptr) {
		goto errorReturn;
	}

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT),
			COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}

	//  Build protected headers

	if (!CreateSign1AAD(pSign, &pbToSign, &cbToSign, "Signature1", perr)) {
		goto errorReturn;
	}

	switch (alg) {
#ifdef USE_ECDSA_SHA_256
		case COSE_Algorithm_ECDSA_SHA_256:
			if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE + 1, pKey, 256,
					pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDSA_SHA_384
		case COSE_Algorithm_ECDSA_SHA_384:
			if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE + 1, pKey, 384,
					pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDSA_SHA_512
		case COSE_Algorithm_ECDSA_SHA_512:
			if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE + 1, pKey, 512,
					pbToSign, cbToSign, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_EDDSA
		case COSE_Algorithm_EdDSA:
			if (!EdDSA_Verify(&pSign->m_message, INDEX_SIGNATURE + 1, pKey,
					pbToSign, cbToSign, perr)) {
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
	if (pbToSign != nullptr) {
		COSE_FREE(pbToSign, context);
	}

	return fRet;
}

#endif
