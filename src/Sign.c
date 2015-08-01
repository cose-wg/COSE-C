#include <stdlib.h>

#include "cose.h"
#include "cose_int.h"

bool IsValidSignHandle(HCOSE_SIGN h)
{
	COSE_SignMessage * p = (COSE_SignMessage *)h;
	if (p == NULL) return false;
	return true;
}


HCOSE_SIGN COSE_Sign_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_SignMessage * pobj = (COSE_SignMessage *)COSE_CALLOC(1, sizeof(COSE_SignMessage), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, CBOR_CONTEXT_PARAM_COMMA perror)) {
	error_setup:
		COSE_Sign_Free((HCOSE_SIGN)pobj);
		return NULL;
	}

	if (!cn_cbor_mapput_int(pobj->m_message.m_cbor, COSE_Header_Type, cn_cbor_int_create(2, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		goto error_setup;
	}

	return (HCOSE_SIGN)pobj;
}

HCOSE_SIGN _COSE_Sign_Init_From_Object(cn_cbor * cbor, COSE_SignMessage * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_SignMessage * pobj = pIn;
	cn_cbor * pSigners = NULL;
	// cn_cbor * tmp;
	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_SignMessage *)COSE_CALLOC(1, sizeof(COSE_SignMessage), context);
	if (pobj == NULL) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if ((pIn == NULL) && (pobj != NULL)) COSE_FREE(pobj, context);
		return NULL;
	}

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	pSigners = (cn_cbor *)cn_cbor_mapget_int(cbor, COSE_Header_Recipients);
	if (pSigners != NULL) {
		CHECK_CONDITION(pSigners->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

		pSigners = pSigners->first_child;
		while (pSigners != NULL) {
			COSE_SignerInfo * pInfo = _COSE_SignerInfo_Init_From_Object(pSigners, CBOR_CONTEXT_PARAM_COMMA perr);
			CHECK_CONDITION(pInfo != NULL, COSE_ERR_OUT_OF_MEMORY);

			pInfo->m_signerNext = pobj->m_signerFirst;
			pobj->m_signerFirst = pInfo;
			pSigners = pSigners->next;
		}
	}

	return(HCOSE_SIGN)pobj;
}

bool COSE_Sign_Free(HCOSE_SIGN h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif

	if (!IsValidSignHandle(h)) return false;

#ifdef USE_CBOR_CONTEXT
	context = ((COSE_SignMessage *)h)->m_message.m_allocContext;
#endif

	_COSE_Sign_Release((COSE_SignMessage *)h);

	COSE_FREE((COSE_SignMessage *)h, &context);

	return true;
}

void _COSE_Sign_Release(COSE_SignMessage * p)
{
	// if (p->pbContent != NULL) COSE_FREE(p->pbContent, &p->m_message.m_allocContext);
	//	if (p->pbIV != NULL) COSE_FREE(p->pbIV, &p->m_message.m_allocContext);
	// if (p->pbKey != NULL) COSE_FREE(p->pbKey, &p->m_message.m_allocContext);

	_COSE_Release(&p->m_message);
}
