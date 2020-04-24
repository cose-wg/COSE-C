#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "crypto.h"

#ifdef USE_COUNTER_SIGNATURES

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

	_COSE_RemoveFromList(&CountersignRoot, &pSigner->m_signer.m_message);

	_COSE_SignerInfo_Release(&pSigner->m_signer);

	COSE_FREE(pSigner, &pSigner->m_signer.m_message.m_allocContext);

	return true;
}

COSE_CounterSign * _COSE_CounterSign_Init_From_Object(cn_cbor* cbor, COSE_CounterSign * pIn, CBOR_CONTEXT_COMMA cose_errback* perr)
{
	COSE_CounterSign* pobj = pIn;

	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) {
		pobj = (COSE_CounterSign*)COSE_CALLOC(1, sizeof(COSE_CounterSign), context);
		CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
    if (!_COSE_SignerInfo_Init_From_Object(cbor, &pobj->m_signer, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
    }

    _COSE_InsertInList(&CountersignRoot, &pobj->m_signer.m_message);

	return pobj;

errorReturn:
	if (pobj != NULL) {
		_COSE_CounterSign_Free(pobj);
	}
	return NULL;
}

bool _COSE_CounterSign_Init(COSE_CounterSign* pobject, CBOR_CONTEXT_COMMA cose_errback* perror)
{
	return _COSE_SignerInfo_Init(COSE_INIT_FLAGS_NO_CBOR_TAG, &pobject->m_signer, COSE_countersign_object, CBOR_CONTEXT_PARAM_COMMA perror);
}

HCOSE_COUNTERSIGN COSE_CounterSign_Init(CBOR_CONTEXT_COMMA cose_errback* perror)
{
	COSE_CounterSign* pobject = (COSE_CounterSign*)COSE_CALLOC(1, sizeof(COSE_CounterSign), context);
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
	return (HCOSE_COUNTERSIGN) pobject;
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

	fRet = _COSE_CounterSign_Free(p);

errorReturn:
	return fRet;
}


///  Add a countersignature to the list used to create the attribute
///
bool _COSE_CounterSign_add(COSE* pMessage, HCOSE_COUNTERSIGN hSigner, cose_errback* perr)
{
	COSE_CounterSign* pSigner = (COSE_CounterSign*)hSigner;

	CHECK_CONDITION(IsValidCounterSignHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pSigner->m_signer.m_message.m_counterSigners == NULL, COSE_ERR_INVALID_PARAMETER);

	pSigner->m_signer.m_message.m_counterSigners = pMessage->m_counterSigners;
	pMessage->m_counterSigners = pSigner;
	return true;

errorReturn:
	return false;
}


HCOSE_COUNTERSIGN COSE_Signer_add_countersignature(HCOSE_SIGNER hSigner, HCOSE_COUNTERSIGN hCountersign, cose_errback* perr)
{
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidCounterSignHandle(hCountersign), COSE_ERR_INVALID_HANDLE);

	if (!_COSE_CounterSign_add(&((COSE_SignerInfo*)hSigner)->m_message, hCountersign, perr)) {
		goto errorReturn;
	}

	return hCountersign;

errorReturn:
	return NULL;
}


/// Get the n-th counter signature from the attribute.
///
HCOSE_COUNTERSIGN _COSE_CounterSign_get(COSE* pMessage, int iSigner, cose_errback* perr)
{
	COSE_CounterSign* pSigner = pMessage->m_counterSigners;
	int i;

	for (i = 0; i < iSigner; i++, pSigner = pSigner->m_next) {
		CHECK_CONDITION(pSigner != NULL, COSE_ERR_INVALID_PARAMETER);
	}

	return (HCOSE_COUNTERSIGN)pSigner;

errorReturn:
	return false;
}

/// _COSE_CounterSign_create
///
///	Create the CounterSign attribute based on the set of countersignatures added to the message.
///

bool _COSE_CounterSign_create(COSE* pMessage, cn_cbor* pcnBody, CBOR_CONTEXT_COMMA cose_errback* perr)
{
	cn_cbor* pArray = NULL;
	cn_cbor_errback cbor_err;
	COSE_CounterSign* pSigner = NULL;
	cn_cbor* pcnProtected = NULL;
	cn_cbor* pcn = NULL;
	cn_cbor* pcn2 = NULL;

	if (pMessage->m_counterSigners == NULL) return true;

	//  One or more than one?
	if (pMessage->m_counterSigners->m_signer.m_signerNext != NULL) {
		pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_err);
		CHECK_CONDITION_CBOR(pArray != NULL, cbor_err);
	}

	pcnProtected = _COSE_arrayget_int(pMessage, INDEX_PROTECTED);
	CHECK_CONDITION(pcnProtected != NULL, COSE_ERR_INTERNAL);

	for (pSigner = pMessage->m_counterSigners; pSigner != NULL; pSigner = pSigner->m_next) {
		CHECK_CONDITION(pSigner->m_signer.m_signerNext == NULL, COSE_ERR_INTERNAL);

		pcn = cn_cbor_data_create(pcnProtected->v.bytes, pcnProtected->length, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
		CHECK_CONDITION_CBOR(pcnProtected != NULL, cbor_err);

		pcn2 = cn_cbor_clone(pcnBody, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
		CHECK_CONDITION_CBOR(pcnBody != NULL, cbor_err);

		if (!_COSE_Signer_sign(&pSigner->m_signer, pcnBody, pcn2, "CounterSignature", perr)) goto errorReturn;
		pcn = NULL;
		pcn2 = NULL;

		if (pArray != NULL) {
			bool f = cn_cbor_array_append(pArray, pSigner->m_signer.m_message.m_cborRoot, &cbor_err);
			CHECK_CONDITION_CBOR(f, cbor_err);
		}
		else {
			pArray = pSigner->m_signer.m_message.m_cborRoot;
		}
	}

	if (!_COSE_map_put(pMessage, COSE_Header_CounterSign, pArray, COSE_UNPROTECT_ONLY, perr)) goto errorReturn;

	return true;

errorReturn:
	if (pArray != NULL) CN_CBOR_FREE(pArray, context);
	if ((pcn != NULL) && (pcn->parent != NULL)) CN_CBOR_FREE(pcn, context);
	if ((pcn2 != NULL) && (pcn2->parent != NULL)) CN_CBOR_FREE(pcn2, context);
	return false;
}

bool COSE_CounterSign_SetKey(HCOSE_COUNTERSIGN h, const cn_cbor* pkey, cose_errback* perr)
{
	bool fRet = false;
	CHECK_CONDITION(IsValidCounterSignHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pkey != NULL, COSE_ERR_INVALID_PARAMETER);

	COSE_CounterSign* p = (COSE_CounterSign*)h;
	p->m_signer.m_pkey = pkey;

	fRet = true;
errorReturn:
	return fRet;
}


COSE_CounterSign* _COSE_Message_get_countersignature(COSE* pMessage, int index, cose_errback* perr)
{
	CHECK_CONDITION(pMessage->m_counterSigners != NULL, COSE_ERR_INVALID_PARAMETER);

	COSE_CounterSign* pCounterSign = pMessage->m_counterSigners;

	for (int i = 0; i < index; i++) {
		pCounterSign = pCounterSign->m_next;
		CHECK_CONDITION(pCounterSign != NULL, COSE_ERR_INVALID_PARAMETER);

	}

	pCounterSign->m_signer.m_message.m_refCount += 1;

	return pCounterSign;

errorReturn:
	return NULL;
}

HCOSE_COUNTERSIGN COSE_Signer_get_countersignature(HCOSE_SIGNER hSigner, int index, cose_errback* perr)
{
	COSE_CounterSign* p = NULL;

	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);

	p = _COSE_Message_get_countersignature(&((COSE_SignerInfo*)hSigner)->m_message, index, perr);

	errorReturn:
	return (HCOSE_COUNTERSIGN)p;
}

bool COSE_CounterSign_validate(HCOSE_SIGNER hSigner, HCOSE_COUNTERSIGN hCountersignature, cose_errback* perr)
{
	bool f;
	COSE_SignerInfo* pSigner;
	COSE_CounterSign* pCountersign;
	const cn_cbor* cnContent;
	const cn_cbor* cnProtected;

	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidCounterSignHandle(hCountersignature), COSE_ERR_INVALID_HANDLE);

	pSigner = (COSE_SignerInfo*)hSigner;
	pCountersign = (COSE_CounterSign*)hCountersignature;

	cnContent = _COSE_arrayget_int(&pSigner->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	cnProtected = _COSE_arrayget_int(&pSigner->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	f = _COSE_Signer_validate(&pCountersign->m_signer, cnContent, cnProtected, "CounterSignature", perr);

	return f;

errorReturn:
	return false;
}


#endif
