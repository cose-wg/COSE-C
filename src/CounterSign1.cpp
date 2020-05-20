#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "cose_crypto.h"

#if INCLUDE_COUNTERSIGNATURE1

COSE* Countersign1Root = nullptr;

bool IsValidCounterSign1Handle(HCOSE_COUNTERSIGN1 h)
{
	COSE_CounterSign1* p = (COSE_CounterSign1*)h;
	return _COSE_IsInList(Countersign1Root, &p->m_signer.m_message);
}

bool _COSE_CounterSign1_Free(COSE_CounterSign1* pSigner)
{
	if (pSigner->m_signer.m_message.m_refCount > 1) {
		pSigner->m_signer.m_message.m_refCount--;
		return true;
	}

	_COSE_SignerInfo_Release(&pSigner->m_signer);

	COSE_FREE(pSigner, &pSigner->m_signer.m_message.m_allocContext);

	return true;
}

COSE_CounterSign1* _COSE_CounterSign1_Init_From_Object(cn_cbor* cbor,
	COSE_CounterSign1* pIn,
	CBOR_CONTEXT_COMMA cose_errback* perr)
{
	COSE_CounterSign1* pobj = pIn;
	cn_cbor* newBody = nullptr;
	cn_cbor* cn2 = nullptr;
	cn_cbor_errback cborError;

	cose_errback error = {COSE_ERR_NONE};
	if (perr == nullptr) {
		perr = &error;
	}

	if (false) {
	errorReturn:
		if (pobj != nullptr && pIn == nullptr) {
			pobj->m_signer.m_message.m_ownMsg = false;
			_COSE_CounterSign1_Free(pobj);
		}
		if (newBody != nullptr) {
			CN_CBOR_FREE(newBody, context);
		}
		if (cn2 != nullptr) {
			CN_CBOR_FREE(cn2, context);
		}
		return nullptr;
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	newBody = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cborError);
	CHECK_CONDITION_CBOR(newBody != NULL, cborError);

	cn2 = cn_cbor_data_create(
		nullptr, 0, CBOR_CONTEXT_PARAM_COMMA & cborError);	// protected = bstr
	CHECK_CONDITION_CBOR(cn2 != NULL, cborError);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(newBody, cn2, &cborError), cborError);

	cn2 = cn_cbor_map_create(
		CBOR_CONTEXT_PARAM_COMMA & cborError);	// unprotected = map
	CHECK_CONDITION_CBOR(cn2 != NULL, cborError);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(newBody, cn2, &cborError), cborError);

	cn2 = cn_cbor_clone(
		cbor, CBOR_CONTEXT_PARAM_COMMA & cborError);  // signature = bstr
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(newBody, cn2, &cborError), cborError);
	cn2 = nullptr;

	if (pobj == nullptr) {
		pobj = (COSE_CounterSign1*)COSE_CALLOC(
			1, sizeof(COSE_CounterSign1), context);
		CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);
	}

	if (!_COSE_SignerInfo_Init_From_Object(
			newBody, &pobj->m_signer, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}
	newBody = nullptr;

	if (pIn == nullptr) {
		_COSE_InsertInList(&Countersign1Root, &pobj->m_signer.m_message);
	}

	return pobj;
}

bool _COSE_CounterSign1_Init(COSE_CounterSign1* pobject,
	CBOR_CONTEXT_COMMA cose_errback* perror)
{
	return _COSE_SignerInfo_Init(COSE_INIT_FLAGS_NO_CBOR_TAG,
		&pobject->m_signer, COSE_CounterSign1_object,
		CBOR_CONTEXT_PARAM_COMMA perror);
}

HCOSE_COUNTERSIGN1 COSE_CounterSign1_Init(
	CBOR_CONTEXT_COMMA cose_errback* perror)
{
	COSE_CounterSign1* pobject =
		(COSE_CounterSign1*)COSE_CALLOC(1, sizeof(COSE_CounterSign1), context);
	if (pobject == nullptr) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_OUT_OF_MEMORY;
		}
		return nullptr;
	}

	if (!_COSE_CounterSign1_Init(pobject, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_CounterSign1_Free(pobject);
		return nullptr;
	}

	_COSE_InsertInList(&Countersign1Root, &pobject->m_signer.m_message);
	return (HCOSE_COUNTERSIGN1)pobject;
}

bool COSE_CounterSign1_Free(HCOSE_COUNTERSIGN1 h)
{
	COSE_CounterSign1* p = (COSE_CounterSign1*)h;
	bool fRet = false;

	if (!IsValidCounterSign1Handle(h)) {
		goto errorReturn;
	}

	if (p->m_signer.m_message.m_refCount > 1) {
		p->m_signer.m_message.m_refCount--;
		return true;
	}

	_COSE_RemoveFromList(&Countersign1Root, &p->m_signer.m_message);

	fRet = _COSE_CounterSign1_Free(p);

errorReturn:
	return fRet;
}

///  Add a countersignature to the list used to create the attribute
///
bool _COSE_CounterSign1_add(COSE* pMessage,
	HCOSE_COUNTERSIGN1 hSigner,
	cose_errback* perr)
{
	COSE_CounterSign1* pSigner = (COSE_CounterSign1*)hSigner;

	CHECK_CONDITION(
		IsValidCounterSign1Handle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pSigner->m_next == NULL, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(
		pMessage->m_counterSign1 == NULL, COSE_ERR_INVALID_PARAMETER);

	pMessage->m_counterSign1 = pSigner;
	pSigner->m_signer.m_message.m_refCount += 1;
	return true;

errorReturn:
	return false;
}

#if 0
I Don't remember why I wrote this and if I don't need it any more.
Keep for a little while and then delete
/// _COSE_CounterSign1_create
///
///	Create the CounterSign attribute based on the set of countersignatures added
/// to the message.
///

bool _COSE_CounterSign1_create(COSE* pMessage,
	cn_cbor* pcnBody,
	CBOR_CONTEXT_COMMA cose_errback* perr)
{
	cn_cbor* pArray = NULL;
	cn_cbor_errback cbor_err;
	COSE_CounterSign1* pSigner = NULL;
	cn_cbor* pcnProtected = NULL;
	cn_cbor* pcn = NULL;
	cn_cbor* pcn2 = NULL;

	if (pMessage->m_counterSigners == NULL) {
		return true;
	}

	//  One or more than one?
	if (pMessage->m_counterSigners->m_signer.m_signerNext != NULL) {
		pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_err);
		CHECK_CONDITION_CBOR(pArray != NULL, cbor_err);
	}

	pcnProtected = _COSE_arrayget_int(pMessage, INDEX_PROTECTED);
	CHECK_CONDITION(pcnProtected != NULL, COSE_ERR_INTERNAL);

	for (pSigner = pMessage->m_counterSigners; pSigner != NULL;
		 pSigner = pSigner->m_next) {
		CHECK_CONDITION(
			pSigner->m_signer.m_signerNext == NULL, COSE_ERR_INTERNAL);

		pcn = cn_cbor_data_create(pcnProtected->v.bytes, pcnProtected->length,
			CBOR_CONTEXT_PARAM_COMMA & cbor_err);
		CHECK_CONDITION_CBOR(pcnProtected != NULL, cbor_err);

		pcn2 = cn_cbor_clone(pcnBody, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
		CHECK_CONDITION_CBOR(pcnBody != NULL, cbor_err);

		if (!_COSE_Signer_sign(
				&pSigner->m_signer, pcnBody, pcn2, "CounterSignature", perr)) {
			goto errorReturn;
		}
		pcn = NULL;
		pcn2 = NULL;

		if (pArray != NULL) {
			bool f = cn_cbor_array_append(
				pArray, pSigner->m_signer.m_message.m_cborRoot, &cbor_err);
			CHECK_CONDITION_CBOR(f, cbor_err);
		}
		else {
			pArray = pSigner->m_signer.m_message.m_cborRoot;
		}
	}

	if (!_COSE_map_put(pMessage, COSE_Header_CounterSign1, pArray,
			COSE_UNPROTECT_ONLY, perr)) {
		goto errorReturn;
	}

	return true;

errorReturn:
	if (pArray != NULL) {
		CN_CBOR_FREE(pArray, context);
	}
	if ((pcn != NULL) && (pcn->parent != NULL)) {
		CN_CBOR_FREE(pcn, context);
	}
	if ((pcn2 != NULL) && (pcn2->parent != NULL)) {
		CN_CBOR_FREE(pcn2, context);
	}
	return false;
}
#endif

#if 0
bool COSE_CounterSign1_SetKey(HCOSE_COUNTERSIGN1 h,
	const cn_cbor* pkey,
	cose_errback* perr)
{
	bool fRet = false;
	HCOSE_KEY coseKey = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context* context = NULL;
#endif

	CHECK_CONDITION(pkey != NULL, COSE_ERR_INVALID_PARAMETER);
	coseKey = COSE_KEY_FromCbor((cn_cbor*)pkey, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(coseKey != NULL, COSE_ERR_OUT_OF_MEMORY);

	fRet = COSE_CounterSign1_SetKey(h, coseKey, perr);

errorReturn:
	if (coseKey != NULL) {
		COSE_KEY_Free(coseKey);
	}
	return fRet;
}
#endif

bool COSE_CounterSign1_SetKey(HCOSE_COUNTERSIGN1 hSigner,
	HCOSE_KEY hKey,
	cose_errback* perr)
{
	bool fRet = false;
	COSE_CounterSign1* pSigner = (COSE_CounterSign1*)hSigner;
	COSE_KEY* pKey = (COSE_KEY*)hKey;

	CHECK_CONDITION(
		IsValidCounterSign1Handle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidKeyHandle(hKey), COSE_ERR_INVALID_HANDLE);

	if (pSigner->m_signer.m_pkey != nullptr) {
		COSE_KEY_Free((HCOSE_KEY)pSigner->m_signer.m_pkey);
	}

	pSigner->m_signer.m_pkey = pKey;
	if (hKey != nullptr) {
		pKey->m_refCount += 1;
	}
	fRet = true;

errorReturn:
	return fRet;
}

COSE_CounterSign1* _COSE_Message_get_countersignature1(COSE* pMessage,
	cose_errback* perr)
{
	COSE_CounterSign1* pCounterSign = pMessage->m_counterSign1;
	CHECK_CONDITION(
		pMessage->m_counterSign1 != NULL, COSE_ERR_INVALID_PARAMETER);

	if (pCounterSign != nullptr) {
		pCounterSign->m_signer.m_message.m_refCount += 1;
	}
	return pCounterSign;

errorReturn:
	return nullptr;
}

bool COSE_CounterSign1_map_put_int(HCOSE_COUNTERSIGN1 h,
	int key,
	cn_cbor* value,
	int flags,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidCounterSign1Handle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

	return _COSE_map_put(
		&((COSE_CounterSign1*)h)->m_signer.m_message, key, value, flags, perr);

errorReturn:
	return false;
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

bool COSE_CounterSign1_SetExternal(HCOSE_COUNTERSIGN1 hcose,
	const byte* pbExternalData,
	size_t cbExternalData,
	cose_errback* perr)
{
	if (!IsValidCounterSign1Handle(hcose)) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_INVALID_HANDLE;
		}
		return false;
	}

	return _COSE_SetExternal(&((COSE_CounterSign1*)hcose)->m_signer.m_message,
		pbExternalData, cbExternalData, perr);
}

bool _COSE_CounterSign1_Sign(COSE* baseMessage,
	CBOR_CONTEXT_COMMA cose_errback* perr)
{
	bool fRet = false;
	cn_cbor* pcborProtectedSign = nullptr;
	cn_cbor_errback cborerr;
	byte* sigValue = nullptr;
	cn_cbor* cn3 = nullptr;

	if (false) {
	errorReturn:
		if (sigValue != nullptr) {
			COSE_FREE(sigValue, context);
		}
		if (cn3 != nullptr) {
			CN_CBOR_FREE(cn3, context);
		}
		return fRet;
	}

	cn_cbor* pSignature = _COSE_arrayget_int(baseMessage, INDEX_SIGNATURE);

	COSE_CounterSign1* pCountersign = baseMessage->m_counterSign1;
	pcborProtectedSign = _COSE_encode_protected(baseMessage, perr);
	if (pcborProtectedSign == nullptr) {
		goto errorReturn;
	}
	if (!_COSE_Signer_sign(&pCountersign->m_signer, pSignature,
			pcborProtectedSign, "CounterSignature0", perr)) {
		goto errorReturn;
	}

	cn_cbor* cn = COSE_get_cbor((HCOSE)baseMessage->m_counterSign1);
	cn = cn_cbor_index(cn, 2);
	sigValue = (byte*)COSE_CALLOC(cn->length, 1, context);
	CHECK_CONDITION(sigValue != NULL, COSE_ERR_OUT_OF_MEMORY);
	memcpy(sigValue, cn->v.bytes, cn->length);
	cn3 = cn_cbor_data_create2(
		sigValue, cn->length, 0, CBOR_CONTEXT_PARAM_COMMA & cborerr);
	CHECK_CONDITION_CBOR(cn3 != NULL, cborerr);
	sigValue = nullptr;

	CHECK_CONDITION(_COSE_map_put(baseMessage, COSE_Header_CounterSign1, cn3,
						COSE_UNPROTECT_ONLY, perr),
		COSE_ERR_OUT_OF_MEMORY);
	cn3 = nullptr;

	fRet = true;
	goto errorReturn;
}

/*! brief Retrieve header parameter from an enveloped message structure
 *
 * Retrieve a header parameter from the message.
 * Retrieved object is the same as the one in the message - do not delete it
 *
 * @param[in]	h	Handle of recipient object
 * @param[in]    key	Key to look for
 * @param[in]	flags	What buckets should we look for the message
 * @param[out]	perror	Location to return error codes
 * @return	Object which is found or NULL
 */

cn_cbor* COSE_CounterSign1_map_get_int(HCOSE_COUNTERSIGN1 h,
	int key,
	int flags,
	cose_errback* perror)
{
	if (!IsValidCounterSign1Handle(h)) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_INVALID_HANDLE;
		}
		return nullptr;
	}

	return _COSE_map_get_int(
		&((COSE_CounterSign1*)h)->m_signer.m_message, key, flags, perror);
}

#if INCLUDE_SIGN
/***************************************************************************************************
 *
 *   SIGNER
 */
HCOSE_COUNTERSIGN1 COSE_Signer_add_countersignature1(HCOSE_SIGNER hSigner,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_SignerInfo*)hSigner)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Signer_get_countersignature1(HCOSE_SIGNER hSigner,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_SignerInfo*)hSigner)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Signer_CounterSign1_validate(HCOSE_SIGNER hSigner,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_SignerInfo* pSigner = (COSE_SignerInfo*)hSigner;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSigner->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSigner->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}

/***************************************************************************************************
 *
 *   SIGN MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Sign_add_countersignature1(HCOSE_SIGN hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidSignHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Sign_get_countersignature1(HCOSE_SIGN hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidSignHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_SignMessage*)hSignMsg)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Sign_CounterSign1_validate(HCOSE_SIGN hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidSignHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_SignMessage* pSignMsg = (COSE_SignMessage*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#if INCLUDE_SIGN1
/***************************************************************************************************
 *
 *   SIGN1 MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Sign1_add_countersignature1(HCOSE_SIGN1 hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidSign1Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Sign1_get_countersignature1(HCOSE_SIGN1 hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidSign1Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_SignMessage*)hSignMsg)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Sign1_CounterSign1_validate(HCOSE_SIGN1 hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidSign1Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Sign1Message* pSignMsg = (COSE_Sign1Message*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#if INCLUDE_ENCRYPT
/***************************************************************************************************
 *
 *   ENVELOPED MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Enveloped_add_countersignature1(
	HCOSE_ENVELOPED hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidEnvelopedHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_Enveloped*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Enveloped_get_countersignature1(
	HCOSE_ENVELOPED hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidEnvelopedHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_Enveloped*)hSignMsg)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Enveloped_CounterSign1_validate(HCOSE_ENVELOPED hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}
	CHECK_CONDITION(IsValidEnvelopedHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Enveloped* pSignMsg = (COSE_Enveloped*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
/***************************************************************************************************
 *
 *   RECIPIENT MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Recipient_add_countersignature1(
	HCOSE_RECIPIENT hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidRecipientHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_RecipientInfo*)hSignMsg)->m_encrypt.m_message, hCountersign,
			perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Recipient_get_countersignature1(
	HCOSE_RECIPIENT hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidRecipientHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_RecipientInfo*)hSignMsg)->m_encrypt.m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Recipient_CounterSign1_validate(HCOSE_RECIPIENT hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidRecipientHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_RecipientInfo* pSignMsg = (COSE_RecipientInfo*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_encrypt.m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_encrypt.m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#if INCLUDE_ENCRYPT0
/***************************************************************************************************
 *
 *   ENCRYPT0 MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Encrypt0_add_countersignature1(HCOSE_ENCRYPT hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidEncryptHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Encrypt0_get_countersignature1(HCOSE_ENCRYPT hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidEncryptHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_SignMessage*)hSignMsg)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Encrypt0_CounterSign1_validate(HCOSE_ENCRYPT hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidEncryptHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Encrypt* pSignMsg = (COSE_Encrypt*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#if INCLUDE_MAC0
/***************************************************************************************************
 *
 *   MAC0 MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Mac0_add_countersignature1(HCOSE_MAC0 hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidMac0Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Mac0_get_countersignature1(HCOSE_MAC0 hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidMac0Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_SignMessage*)hSignMsg)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Mac0_CounterSign1_validate(HCOSE_MAC0 hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidMac0Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Mac0Message* pSignMsg = (COSE_Mac0Message*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#if INCLUDE_MAC
/***************************************************************************************************
 *
 *   ENCRYPT0 MESSAGE
 */
HCOSE_COUNTERSIGN1 COSE_Mac_add_countersignature1(HCOSE_MAC hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidMacHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign1_add(
			&((COSE_MacMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return nullptr;
}

HCOSE_COUNTERSIGN1 COSE_Mac_get_countersignature1(HCOSE_MAC hSignMsg,
	cose_errback* perr)
{
	COSE_CounterSign1* p = nullptr;

	CHECK_CONDITION(IsValidMacHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature1(
		&((COSE_MacMessage*)hSignMsg)->m_message, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN1)p;
}

bool COSE_Mac_CounterSign1_validate(HCOSE_MAC hSignMsg,
	HCOSE_COUNTERSIGN1 hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;
	}

	CHECK_CONDITION(IsValidMacHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSign1Handle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_MacMessage* pSignMsg = (COSE_MacMessage*)hSignMsg;
	COSE_CounterSign1* pCountersign = (COSE_CounterSign1*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature0", perr);

	return f;
}
#endif

#endif
