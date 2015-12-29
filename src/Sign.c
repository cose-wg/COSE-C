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

	if (!_COSE_Init(&pobj->m_message, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		COSE_Sign_Free((HCOSE_SIGN)pobj);
		return NULL;
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

bool COSE_Sign_SetContent(HCOSE_SIGN h, const byte * rgb, size_t cb, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	cn_cbor * p = NULL;
	COSE_SignMessage * pMessage = (COSE_SignMessage *)h;

	if (!IsValidSignHandle(h) || (rgb == NULL)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
	errorReturn:
		if (p != NULL) CN_CBOR_FREE(p, context);
		return false;
	}

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	p = cn_cbor_data_create(rgb, cb, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(p != NULL, COSE_ERR_OUT_OF_MEMORY);

#ifdef USE_ARRAY
	CHECK_CONDITION(_COSE_array_replace(&pMessage->m_message, p, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_OUT_OF_MEMORY);
#else
	CHECK_CONDITION(cn_cbor_mapput_int(pMessage->m_message.m_cbor, COSE_Header_Ciphertext, p, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_OUT_OF_MEMORY);
#endif

	return true;
}

HCOSE_SIGNER COSE_Sign_add_signer(HCOSE_SIGN hSign, const cn_cbor * pkey, int algId, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	COSE_SignMessage * pMessage = (COSE_SignMessage *)hSign;
	COSE_SignerInfo * pSigner = NULL;
	const cn_cbor * cbor;
	cn_cbor * cbor2 = NULL;

	if (!IsValidSignHandle(hSign) || (pkey == NULL)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
	errorReturn:
		if (cbor2 != NULL) CN_CBOR_FREE((void *) cbor2, context);
		if (pSigner != NULL) _COSE_Signer_Free(pSigner);
		return NULL;
	}

	switch (algId) {
	case COSE_Algorithm_ECDSA_SHA_256:
		cbor = cn_cbor_mapget_int(pkey, COSE_Key_Type);
		CHECK_CONDITION(cbor != NULL, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION((cbor->type == CN_CBOR_UINT) && (cbor->v.uint == COSE_Key_Type_EC2), CN_CBOR_ERR_INVALID_PARAMETER);
		break;

	default:
		CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
	}

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	pSigner = (COSE_SignerInfo *)COSE_CALLOC(1, sizeof(COSE_SignerInfo), context);
	CHECK_CONDITION(pSigner != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(&pSigner->m_message, COSE_unknown_object, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;

	cbor = cn_cbor_mapget_int(pkey, COSE_Key_ID);
	if (cbor != NULL) {
		CHECK_CONDITION(cbor->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		cbor2 = cn_cbor_data_create(cbor->v.bytes, cbor->length, CBOR_CONTEXT_PARAM_COMMA NULL);
		CHECK_CONDITION(cbor2 != NULL, COSE_ERR_CBOR);
		CHECK_CONDITION(cn_cbor_mapput_int(pSigner->m_message.m_unprotectMap, COSE_Parameter_KID, cbor2, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
		cbor2 = NULL;
	}

	pSigner->m_pkey = pkey;

	pSigner->m_signerNext = pMessage->m_signerFirst;
	pMessage->m_signerFirst = pSigner;

#ifdef USE_ARRAY
	cn_cbor * pSigners = cn_cbor_index(pMessage->m_message.m_cbor, INDEX_SIGNATURES+1);   // M00BUG
#else
	cn_cbor * pSigners = (cn_cbor *)cn_cbor_mapget_int(pMessage->m_message.m_cbor, COSE_Header_Signers);
#endif
	if (pSigners == NULL) {
		pSigners = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
		CHECK_CONDITION(pSigners != NULL, COSE_ERR_OUT_OF_MEMORY);
#ifdef USE_ARRAY
		if (!_COSE_array_replace(&pMessage->m_message, pSigners, INDEX_SIGNATURES, CBOR_CONTEXT_PARAM_COMMA NULL)) {
			CN_CBOR_FREE(pSigners, context);
			CHECK_CONDITION(false, COSE_ERR_CBOR);
		}
#else
		if (!cn_cbor_mapput_int(pMessage->m_message.m_cbor, COSE_Header_Signers, pSigners, CBOR_CONTEXT_PARAM_COMMA NULL)) {
			CN_CBOR_FREE(pSigners, context);
			CHECK_CONDITION(false, COSE_ERR_CBOR);
		}
#endif
	}

	CHECK_CONDITION(cn_cbor_array_append(pSigners, pSigner->m_message.m_cbor, NULL), COSE_ERR_CBOR);

	return (HCOSE_SIGNER)pSigner;
}

bool COSE_Sign_Sign(HCOSE_SIGN h, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
  // cn_cbor_context * context = NULL;
#endif
	COSE_SignMessage * pMessage = (COSE_SignMessage *)h;
	COSE_SignerInfo * pSigner;
	const cn_cbor * pcborBody;
	const cn_cbor * pcborProtected;

	if (!IsValidSignHandle(h)) {
		CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
	errorReturn:
		return false;
	}
#ifdef USE_CBOR_CONTEXT
	//	context = &pMessage->m_message.m_allocContext;
#endif

#ifdef USE_ARRAY
	pcborBody = _COSE_arrayget_int(&pMessage->m_message, INDEX_BODY);
	CHECK_CONDITION((pcborBody != NULL) && (pcborBody->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);
#else
	//  From this layer we use the protected fields and the body
	pcborBody = cn_cbor_mapget_int(pMessage->m_message.m_cbor, COSE_Header_Ciphertext);
	CHECK_CONDITION(pcborBody != NULL, COSE_ERR_INVALID_PARAMETER);
#endif

	pcborProtected = _COSE_encode_protected(&pMessage->m_message, perr);
	if (pcborProtected == NULL) goto errorReturn;

	for (pSigner = pMessage->m_signerFirst; pSigner != NULL; pSigner = pSigner->m_signerNext) {
		if (!_COSE_Signer_sign(pSigner, pcborBody, pcborProtected, perr)) goto errorReturn;
	}

	return true;
}
