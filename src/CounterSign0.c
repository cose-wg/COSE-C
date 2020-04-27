#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "crypto.h"

#if USE_COUNTER_SIGNATURE1

extern bool IsValidCounterSign1Handle(HCOSE_COUNTERSIGN1 h);


bool _COSE_CounterSign1_add(COSE* pMessage, HCOSE_COUNTERSIGN1 hSigner, cose_errback* perr)
{
	COSE_CounterSign1* pSigner = (COSE_CounterSign1*)hSigner;

	CHECK_CONDITION(IsValidCounterSign1Handle(hSigner), COSE_ERR_INVALID_HANDLE);

	pMessage->m_counterSign1 = pSigner;
	return true;

errorReturn:
	return false;
}

HCOSE_COUNTERSIGN _COSE_CounterSign1_get(COSE* pMessage, cose_errback* perr)
{
	UNUSED(perr);

	COSE_CounterSign1* pSigner = pMessage->m_counterSign1;

	return (HCOSE_COUNTERSIGN)pSigner;
}

bool _COSE_CountSign_create(COSE* pMessage, cn_cbor* pcnBody, CBOR_CONTEXT_COMMA cose_errback* perr)
{
	cn_cbor* pArray = NULL;
	cn_cbor_errback cbor_err;
	COSE_CounterSign1* pSigner = NULL;
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

		pcn = cn_cbor_data_create(pcnProtected->v.bytes, pcnProtected->v.count, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
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

  
