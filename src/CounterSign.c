#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "crypto.h"

#ifdef USE_COUNTER_SIGNATURES

HCOSE_COUNTERSIGN COSE_CounterSign_Init_From_Object(cn_cbor* cbor, CBOR_CONTEXT_COMMA cose_errback* perr)
{
	COSE_Encrypt* pobj;

	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	pobj = (COSE_Encrypt*)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	if (pobj == NULL) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pobj != NULL) {
			_COSE_Encrypt_Release(pobj);
			COSE_FREE(pobj, context);
		}
		return NULL;
	}




///  Add a countersignature to the list used to create the attribute
///
bool _COSE_CounterSign_add(COSE* pMessage, HCOSE_COUNTERSIGN hSigner, cose_errback* perr)
{
	COSE_CounterSign* pSigner = (COSE_CounterSign*)hSigner;

	CHECK_CONDITION(IsValidCounterSignHandle(hSigner), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pSigner->m_signer.m_signerNext == NULL, COSE_ERR_INVALID_PARAMETER);

	pSigner = pMessage->m_counterSigners;
	pMessage->m_counterSigners = pSigner;
	return true;

errorReturn:
	return false;
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

/// _COSE_CountSign_create
///
///	Create the CounterSign attribute based on the set of countersignatures added to the message.
///

bool _COSE_CountSign_create(COSE* pMessage, cn_cbor* pcnBody, CBOR_CONTEXT_COMMA cose_errback* perr)
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

		if (!_COSE_Signer_sign(&pSigner->m_signer, pcnBody, pcn2, perr)) goto errorReturn;
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

#endif

