#include <stdlib.h>
#include <memory.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

extern bool IsValidSignHandle(HCOSE_SIGN h);

bool IsValidSignerHandle(HCOSE_SIGNER h)
{
	if (h == NULL) return false;
	return true;
}

void _COSE_Signer_Free(COSE_SignerInfo * pSigner)
{
	COSE_FREE(pSigner, &pSigner->m_message.m_allocContext);

	return;
}


HCOSE_SIGNER COSE_Sign_GetSigner(HCOSE_SIGN cose, int iSigner, cose_errback * perr)
{
	int i;
	COSE_SignerInfo * p;

	if (!IsValidSignHandle(cose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	p = ((COSE_SignMessage *)cose)->m_signerFirst;
	for (i = 0; i < iSigner; i++) {
		if (p == NULL) {
			if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
			return NULL;
		}
		p = p->m_signerNext;
	}
	return (HCOSE_SIGNER)p;
}

COSE_SignerInfo * _COSE_SignerInfo_Init_From_Object(cn_cbor * cbor, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_SignerInfo * pSigner = NULL;

	pSigner = (COSE_SignerInfo *)COSE_CALLOC(1, sizeof(COSE_SignerInfo), context);
	if (pSigner == NULL) {
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (cbor->type != CN_CBOR_MAP) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		COSE_FREE(pSigner, context);
		return NULL;
	}
	if (!_COSE_Init_From_Object(&pSigner->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Signer_Free(pSigner);
		return NULL;
	}

	return pSigner;
}
