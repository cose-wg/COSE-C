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

byte RgbDontUse4[1024];

bool _COSE_Signer_sign(COSE_SignerInfo * pSigner, const cn_cbor * pcborBody, const cn_cbor * pcborProtected, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * pcborBody2 = NULL;
	cn_cbor * pcborProtected2 = NULL;
	cn_cbor * pcborProtectedSign = NULL;
	cn_cbor * pcborProtectedSign2 = NULL;
	cn_cbor * pArray = NULL;
	size_t cbToSign;
	byte * pbToSign = NULL;
	bool f;

	pArray = cn_cbor_array_create(context, NULL);
	if (pArray == NULL) {
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pcborBody2 != NULL) CN_CBOR_FREE(pcborBody2, context);
		if (pcborProtected2 != NULL) CN_CBOR_FREE(pcborProtected2, context);
		if (pArray != NULL) COSE_FREE(pArray, context);
		if (pbToSign != NULL) COSE_FREE(pbToSign, context);
		return false;
	}

	pcborProtectedSign = _COSE_encode_protected(&pSigner->m_message, perr);
	if (pcborProtectedSign == NULL) goto errorReturn;

	pcborBody2 = cn_cbor_data_create(pcborBody->v.str, pcborBody->length, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pcborBody2 != NULL, COSE_ERR_OUT_OF_MEMORY);

	pcborProtected2 = cn_cbor_data_create(pcborProtected->v.str, pcborProtected->length, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pcborProtected2 != NULL, COSE_ERR_OUT_OF_MEMORY);

	pcborProtectedSign2 = cn_cbor_data_create(pcborProtectedSign->v.str, pcborProtectedSign->length, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pcborProtectedSign2 != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(cn_cbor_array_append(pArray, pcborProtected2, NULL), COSE_ERR_CBOR);
	CHECK_CONDITION(cn_cbor_array_append(pArray, pcborProtectedSign2, NULL), COSE_ERR_CBOR);
	CHECK_CONDITION(cn_cbor_array_append(pArray, cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA NULL), NULL), COSE_ERR_CBOR);
	CHECK_CONDITION(cn_cbor_array_append(pArray, pcborBody2, NULL), COSE_ERR_CBOR);

	cbToSign = cn_cbor_encoder_write(RgbDontUse4, 0, sizeof(RgbDontUse4), pArray);
	CHECK_CONDITION(cbToSign > 0, COSE_ERR_CBOR);
	pbToSign = (byte *)COSE_CALLOC(cbToSign, 1, context);
	CHECK_CONDITION(pbToSign != NULL, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(cn_cbor_encoder_write(pbToSign, 0, cbToSign, pArray), COSE_ERR_CBOR);

	f = ECDSA_Sign(pSigner, pbToSign, cbToSign, perr);

	COSE_FREE(pbToSign, context);
	CN_CBOR_FREE(pArray, context);

	return f;
}
