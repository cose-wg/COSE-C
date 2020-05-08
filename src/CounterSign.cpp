#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "cose_crypto.h"

#if INCLUDE_COUNTERSIGNATURE

COSE* CountersignRoot = NULL;

bool IsValidCounterSignHandle(HCOSE_COUNTERSIGN h)
{
	COSE_CounterSign* p = (COSE_CounterSign*)h;
	return _COSE_IsInList(CountersignRoot, &p->m_signer.m_message);
}

bool _COSE_CounterSign_Free(COSE_CounterSign* pSigner)
{
	if (pSigner->m_signer.m_message.m_refCount > 1) {
		pSigner->m_signer.m_message.m_refCount--;
		return true;
	}

	_COSE_SignerInfo_Release(&pSigner->m_signer);

	COSE_FREE(pSigner, &pSigner->m_signer.m_message.m_allocContext);

	return true;
}

COSE_CounterSign* _COSE_CounterSign_Init_From_Object(cn_cbor* cbor,
	COSE_CounterSign* pIn,
	CBOR_CONTEXT_COMMA cose_errback* perr)
{
	COSE_CounterSign* pobj = pIn;

	cose_errback error = {COSE_ERR_NONE};
	if (perr == NULL) {
		perr = &error;
	}

	if (pobj == NULL) {
		pobj = (COSE_CounterSign*)COSE_CALLOC(
			1, sizeof(COSE_CounterSign), context);
		CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
	if (!_COSE_SignerInfo_Init_From_Object(
			cbor, &pobj->m_signer, CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_SignerInfo_Release(&pobj->m_signer);
		if (pIn == NULL) {
			COSE_FREE(pobj, context);
		}
		return NULL;
	}

	if (pIn == NULL) {
		_COSE_InsertInList(&CountersignRoot, &pobj->m_signer.m_message);
	}

	return pobj;

errorReturn:
	if (pobj != NULL) {
		_COSE_CounterSign_Free(pobj);
	}
	return NULL;
}

bool _COSE_CounterSign_Init(COSE_CounterSign* pobject,
	CBOR_CONTEXT_COMMA cose_errback* perror)
{
	return _COSE_SignerInfo_Init(COSE_INIT_FLAGS_NO_CBOR_TAG,
		&pobject->m_signer, COSE_countersign_object,
		CBOR_CONTEXT_PARAM_COMMA perror);
}

HCOSE_COUNTERSIGN COSE_CounterSign_Init(CBOR_CONTEXT_COMMA cose_errback* perror)
{
	COSE_CounterSign* pobject =
		(COSE_CounterSign*)COSE_CALLOC(1, sizeof(COSE_CounterSign), context);
	if (pobject == NULL) {
		if (perror != NULL) {
			perror->err = COSE_ERR_OUT_OF_MEMORY;
		}
		return NULL;
	}

	if (!_COSE_CounterSign_Init(pobject, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_CounterSign_Free(pobject);
		return NULL;
	}

	_COSE_InsertInList(&CountersignRoot, &pobject->m_signer.m_message);
	return (HCOSE_COUNTERSIGN)pobject;
}

bool COSE_CounterSign_Free(HCOSE_COUNTERSIGN h)
{
	COSE_CounterSign* p = (COSE_CounterSign*)h;
	bool fRet = false;

	if (!IsValidCounterSignHandle(h)) {
		goto errorReturn;
	}

	if (p->m_signer.m_message.m_refCount > 1) {
		p->m_signer.m_message.m_refCount--;
		return true;
	}

	_COSE_RemoveFromList(&CountersignRoot, &p->m_signer.m_message);

	fRet = _COSE_CounterSign_Free(p);

errorReturn:
	return fRet;
}

///  Add a countersignature to the list used to create the attribute
///
bool _COSE_CounterSign_add(COSE* pMessage,
	HCOSE_COUNTERSIGN hSigner,
	cose_errback* perr)
{
	COSE_CounterSign* pSigner = (COSE_CounterSign*)hSigner;

	CHECK_CONDITION(IsValidCounterSignHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pSigner->m_next == NULL, COSE_ERR_INVALID_PARAMETER);

	pSigner->m_next = pMessage->m_counterSigners;
	pMessage->m_counterSigners = pSigner;
	pSigner->m_signer.m_message.m_refCount += 1;
	return true;

errorReturn:
	return false;
}

#if 0
I Don't remember why I wrote this and if I don't need it any more.
Keep for a little while and then delete
/// _COSE_CounterSign_create
///
///	Create the CounterSign attribute based on the set of countersignatures added
/// to the message.
///

bool _COSE_CounterSign_create(COSE* pMessage,
	cn_cbor* pcnBody,
	CBOR_CONTEXT_COMMA cose_errback* perr)
{
	cn_cbor* pArray = NULL;
	cn_cbor_errback cbor_err;
	COSE_CounterSign* pSigner = NULL;
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

	if (!_COSE_map_put(pMessage, COSE_Header_CounterSign, pArray,
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

bool COSE_CounterSign_SetKey(HCOSE_COUNTERSIGN h,
	const cn_cbor* pkey,
	cose_errback* perr)
{
	bool fRet = false;
	HCOSE_KEY coseKey = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context* context = NULL;
#endif
	
	CHECK_CONDITION(pkey != NULL, COSE_ERR_INVALID_PARAMETER);
	coseKey = COSE_KEY_FromCbor((cn_cbor*) pkey, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(coseKey != NULL, COSE_ERR_OUT_OF_MEMORY);

	fRet = COSE_CounterSign_SetKey2(h, coseKey, perr);

errorReturn:
	if (coseKey != NULL) {
		COSE_KEY_Free(coseKey);
	}
	return fRet;
}

bool COSE_CounterSign_SetKey2(HCOSE_COUNTERSIGN hSigner, HCOSE_KEY hKey, cose_errback* perr)
{
	bool fRet = false;
	COSE_CounterSign* pSigner = (COSE_CounterSign*)hSigner;
	COSE_KEY* pKey = (COSE_KEY*)hKey;

	CHECK_CONDITION(IsValidCounterSignHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidKeyHandle(hKey), COSE_ERR_INVALID_HANDLE);
	
	if (pSigner->m_signer.m_pkey != NULL) {
		COSE_KEY_Free((HCOSE_KEY) pSigner->m_signer.m_pkey);
	}
	
	pSigner->m_signer.m_pkey = pKey;
	if (hKey != NULL) {
		pKey->m_refCount += 1;
	}
	fRet = true;

	errorReturn:
	return fRet;
}

COSE_CounterSign* _COSE_Message_get_countersignature(COSE* pMessage,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* pCounterSign = pMessage->m_counterSigners;
	CHECK_CONDITION(
		pMessage->m_counterSigners != NULL, COSE_ERR_INVALID_PARAMETER);

	for (int i = 0; i < index; i++) {
		pCounterSign = pCounterSign->m_next;
		CHECK_CONDITION(pCounterSign != NULL, COSE_ERR_INVALID_PARAMETER);
	}

	pCounterSign->m_signer.m_message.m_refCount += 1;

	return pCounterSign;

errorReturn:
	return NULL;
}

bool COSE_CounterSign_map_put_int(HCOSE_COUNTERSIGN h,
	int key,
	cn_cbor* value,
	int flags,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidCounterSignHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

	return _COSE_map_put(
		&((COSE_CounterSign*)h)->m_signer.m_message, key, value, flags, perr);

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

bool COSE_CounterSign_SetExternal(HCOSE_COUNTERSIGN hcose,
	const byte* pbExternalData,
	size_t cbExternalData,
	cose_errback* perr)
{
	if (!IsValidCounterSignHandle(hcose)) {
		if (perr != NULL) {
			perr->err = COSE_ERR_INVALID_HANDLE;
		}
		return false;
	}

	return _COSE_SetExternal(&((COSE_CounterSign*)hcose)->m_signer.m_message,
		pbExternalData, cbExternalData, perr);
}

bool _COSE_CounterSign_Sign(COSE* baseMessage,
	CBOR_CONTEXT_COMMA cose_errback* perr)
{
	bool fRet = false;
	cn_cbor* pcborProtectedSign = NULL;

	cn_cbor* pSignature = _COSE_arrayget_int(baseMessage, INDEX_SIGNATURE);
	int count = 0;

	COSE_CounterSign* pCountersign = baseMessage->m_counterSigners;
	for (; pCountersign != NULL;
		 pCountersign = pCountersign->m_next, count += 1) {
		pcborProtectedSign = _COSE_encode_protected(baseMessage, perr);
		if (pcborProtectedSign == NULL) {
			goto errorReturn;
		}
		if (!_COSE_Signer_sign(&pCountersign->m_signer, pSignature,
				pcborProtectedSign, "CounterSignature", perr)) {
			goto errorReturn;
		}
	}

	if (count == 1) {
		cn_cbor* cn = COSE_get_cbor((HCOSE)baseMessage->m_counterSigners);
		CHECK_CONDITION(_COSE_map_put(baseMessage, COSE_Header_CounterSign, cn,
							COSE_UNPROTECT_ONLY, perr),
			COSE_ERR_OUT_OF_MEMORY);
	}
	else {
		cn_cbor_errback cn_error;
		cn_cbor* cn_counterSign =
			cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cn_error);
		CHECK_CONDITION_CBOR(cn_counterSign, cn_error);

		for (pCountersign = baseMessage->m_counterSigners; pCountersign != NULL;
			 pCountersign = pCountersign->m_next) {
			cn_cbor* cn = COSE_get_cbor((HCOSE)pCountersign);
			CHECK_CONDITION_CBOR(
				cn_cbor_array_append(cn_counterSign, cn, &cn_error), cn_error);
		}
		CHECK_CONDITION(_COSE_map_put(baseMessage, COSE_Header_CounterSign,
							cn_counterSign, COSE_UNPROTECT_ONLY, perr),
			COSE_ERR_OUT_OF_MEMORY);
	}

	fRet = true;
errorReturn:
	return fRet;
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

cn_cbor* COSE_CounterSign_map_get_int(HCOSE_COUNTERSIGN h,
	int key,
	int flags,
	cose_errback* perror)
{
	if (!IsValidCounterSignHandle(h)) {
		if (perror != NULL) {
			perror->err = COSE_ERR_INVALID_HANDLE;
		}
		return NULL;
	}

	return _COSE_map_get_int(
		&((COSE_CounterSign*)h)->m_signer.m_message, key, flags, perror);
}

#if INCLUDE_SIGN
/***************************************************************************************************
 *
 *   SIGNER
 */
HCOSE_COUNTERSIGN COSE_Signer_add_countersignature(HCOSE_SIGNER hSigner,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_SignerInfo*)hSigner)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Signer_get_countersignature(HCOSE_SIGNER hSigner,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_SignerInfo*)hSigner)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Signer_CounterSign_validate(HCOSE_SIGNER hSigner,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (0) {
	errorReturn:
		return false;	
	}
	
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_SignerInfo* pSigner = (COSE_SignerInfo*)hSigner;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSigner->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSigner->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;

}

/***************************************************************************************************
 *
 *   SIGN MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Sign_add_countersignature(HCOSE_SIGN hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidSignHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Sign_get_countersignature(HCOSE_SIGN hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidSignHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_SignMessage*)hSignMsg)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Sign_CounterSign_validate(HCOSE_SIGN hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;	
	}
	
	CHECK_CONDITION(IsValidSignHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_SignMessage* pSignMsg = (COSE_SignMessage*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;

}
#endif

#if INCLUDE_SIGN1
/***************************************************************************************************
 *
 *   SIGN1 MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Sign1_add_countersignature(HCOSE_SIGN1 hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidSign1Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Sign1_get_countersignature(HCOSE_SIGN1 hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidSign1Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_SignMessage*)hSignMsg)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Sign1_CounterSign_validate(HCOSE_SIGN1 hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;		
	}
	
	CHECK_CONDITION(IsValidSign1Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Sign1Message* pSignMsg = (COSE_Sign1Message*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;
}
#endif

#if INCLUDE_ENCRYPT
/***************************************************************************************************
 *
 *   ENVELOPED MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Enveloped_add_countersignature(HCOSE_ENVELOPED hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidEnvelopedHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_Enveloped*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Enveloped_get_countersignature(HCOSE_ENVELOPED hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidEnvelopedHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_Enveloped*)hSignMsg)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Enveloped_CounterSign_validate(HCOSE_ENVELOPED hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;		
	}
	CHECK_CONDITION(IsValidEnvelopedHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Enveloped* pSignMsg = (COSE_Enveloped*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
/***************************************************************************************************
 *
 *   RECIPIENT MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Recipient_add_countersignature(HCOSE_RECIPIENT hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidRecipientHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_RecipientInfo*)hSignMsg)->m_encrypt.m_message, hCountersign,
			perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Recipient_get_countersignature(HCOSE_RECIPIENT hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidRecipientHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_RecipientInfo*)hSignMsg)->m_encrypt.m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Recipient_CounterSign_validate(HCOSE_RECIPIENT hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;		
	}
	
	CHECK_CONDITION(IsValidRecipientHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_RecipientInfo* pSignMsg = (COSE_RecipientInfo*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_encrypt.m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_encrypt.m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;
}
#endif

#if INCLUDE_ENCRYPT0
/***************************************************************************************************
 *
 *   ENCRYPT0 MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Encrypt0_add_countersignature(HCOSE_ENCRYPT hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidEncryptHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Encrypt0_get_countersignature(HCOSE_ENCRYPT hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidEncryptHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_SignMessage*)hSignMsg)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Encrypt0_CounterSign_validate(HCOSE_ENCRYPT hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;		
	}
	
	CHECK_CONDITION(IsValidEncryptHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Encrypt* pSignMsg = (COSE_Encrypt*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;
}
#endif

#if INCLUDE_MAC0
/***************************************************************************************************
 *
 *   MAC0 MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Mac0_add_countersignature(HCOSE_MAC0 hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidMac0Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_SignMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Mac0_get_countersignature(HCOSE_MAC0 hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidMac0Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_SignMessage*)hSignMsg)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Mac0_CounterSign_validate(HCOSE_MAC0 hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;		
	}
	
	CHECK_CONDITION(IsValidMac0Handle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_Mac0Message* pSignMsg = (COSE_Mac0Message*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;
}
#endif

#if INCLUDE_MAC
/***************************************************************************************************
 *
 *   ENCRYPT0 MESSAGE
 */
HCOSE_COUNTERSIGN COSE_Mac_add_countersignature(HCOSE_MAC hSignMsg,
	HCOSE_COUNTERSIGN hCountersign,
	cose_errback* perr)
{
	CHECK_CONDITION(IsValidMacHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(
			&((COSE_MacMessage*)hSignMsg)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Mac_get_countersignature(HCOSE_MAC hSignMsg,
	int index,
	cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidMacHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(
		&((COSE_MacMessage*)hSignMsg)->m_message, index, perr);

errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_Mac_CounterSign_validate(HCOSE_MAC hSignMsg,
	HCOSE_COUNTERSIGN hCountersignature,
	cose_errback* perr)
{
	if (false) {
	errorReturn:
		return false;		
	}
	
	CHECK_CONDITION(IsValidMacHandle(hSignMsg), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	COSE_MacMessage* pSignMsg = (COSE_MacMessage*)hSignMsg;
	COSE_CounterSign* pCountersign = (COSE_CounterSign*)hCountersignature;

	const cn_cbor* cnContent =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	const cn_cbor* cnProtected =
		_COSE_arrayget_int(&pSignMsg->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES,
		COSE_ERR_INVALID_PARAMETER);

	bool f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent,
		cnProtected, "CounterSignature", perr);

	return f;
}
#endif

#endif
