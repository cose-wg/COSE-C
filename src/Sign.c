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

	pSigners = _COSE_arrayget_int(&pobj->m_message, INDEX_SIGNERS);
	CHECK_CONDITION(pSigners != NULL, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(pSigners->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

	pSigners = pSigners->first_child;
	CHECK_CONDITION(pSigners != NULL, COSE_ERR_INVALID_PARAMETER);  // Must be at least one signer

	do {
		COSE_SignerInfo * pInfo = _COSE_SignerInfo_Init_From_Object(pSigners, CBOR_CONTEXT_PARAM_COMMA perr);
		if (pInfo == NULL) goto errorReturn;

		pInfo->m_signerNext = pobj->m_signerFirst;
		pobj->m_signerFirst = pInfo;
		pSigners = pSigners->next;
	} while (pSigners != NULL);

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

	p = cn_cbor_data_create(rgb, (int) cb, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(p != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(_COSE_array_replace(&pMessage->m_message, p, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_OUT_OF_MEMORY);

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
	HCOSE_SIGNER hSigner = NULL;
	cn_cbor_errback cbor_error;

	if (!IsValidSignHandle(hSign) || (pkey == NULL)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
	errorReturn:
		if (cbor2 != NULL) CN_CBOR_FREE((void *) cbor2, context);
		if (hSigner != NULL) COSE_Signer_Free(hSigner);
		return NULL;
	}

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	hSigner = COSE_Signer_Init(context, perr);
	if (hSigner == NULL) goto errorReturn;


	cbor2 = cn_cbor_int_create(algId, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cbor2 != NULL, cbor_error);
	if (!COSE_Signer_map_put(hSigner, COSE_Header_Algorithm, cbor2, COSE_PROTECT_ONLY, perr)) goto errorReturn;
	cbor2 = NULL;

	cbor = cn_cbor_mapget_int(pkey, COSE_Key_ID);
	if (cbor != NULL) {
		CHECK_CONDITION(cbor->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		cbor2 = cn_cbor_data_create(cbor->v.bytes, (int) cbor->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(cbor2 != NULL, cbor_error);
		if (!COSE_Signer_map_put(hSigner, COSE_Header_KID, cbor2, COSE_UNPROTECT_ONLY, perr)) goto errorReturn;
		cbor2 = NULL;
	}

	if (!COSE_Signer_SetKey(hSigner, pkey, perr)) goto errorReturn;

	if (!COSE_Sign_AddSigner(hSign, hSigner, perr)) goto errorReturn;

	return hSigner;
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

	pcborBody = _COSE_arrayget_int(&pMessage->m_message, INDEX_BODY);
	CHECK_CONDITION((pcborBody != NULL) && (pcborBody->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

	pcborProtected = _COSE_encode_protected(&pMessage->m_message, perr);
	if (pcborProtected == NULL) goto errorReturn;

	for (pSigner = pMessage->m_signerFirst; pSigner != NULL; pSigner = pSigner->m_signerNext) {
		if (!_COSE_Signer_sign(pSigner, pcborBody, pcborProtected, perr)) goto errorReturn;
	}

	return true;
}

bool COSE_Sign_validate(HCOSE_SIGN hSign, HCOSE_SIGNER hSigner, cose_errback * perr)
{
	bool f;
	COSE_SignMessage * pSign;
	COSE_SignerInfo * pSigner;
	const cn_cbor * cnContent;
	const cn_cbor * cnProtected;

	CHECK_CONDITION(IsValidSignHandle(hSign), COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_PARAMETER);

	pSign = (COSE_SignMessage *)hSign;
	pSigner = (COSE_SignerInfo *)hSigner;

	cnContent = _COSE_arrayget_int(&pSign->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	cnProtected = _COSE_arrayget_int(&pSign->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnContent->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	f = _COSE_Signer_validate(pSign, pSigner, cnContent->v.bytes, cnContent->length, cnProtected->v.bytes, cnProtected->length, perr);

	return f;

errorReturn:
	return false;
}


bool COSE_Sign_AddSigner(HCOSE_SIGN hSign, HCOSE_SIGNER hSigner, cose_errback * perr)
{
	COSE_SignerInfo * pSigner;
	COSE_SignMessage * pSign;
	cn_cbor * pSigners = NULL;
	cn_cbor * pSignersT = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidSignHandle(hSign), COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_PARAMETER);

	pSign = (COSE_SignMessage *)hSign;
	pSigner = (COSE_SignerInfo *)hSigner;

	pSigner->m_signerNext = pSign->m_signerFirst;
	pSign->m_signerFirst = pSigner;

#ifdef USE_CBOR_CONTEXT
	context = &pSign->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	pSigners = _COSE_arrayget_int(&pSign->m_message, INDEX_SIGNERS);
	if (pSigners == NULL) {
		pSignersT = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(pSignersT != NULL, cbor_error);

		CHECK_CONDITION_CBOR(_COSE_array_replace(&pSign->m_message, pSignersT, INDEX_SIGNERS, CBOR_CONTEXT_PARAM_COMMA &cbor_error), cbor_error);
		pSigners = pSignersT;
		pSignersT = NULL;
	}

	CHECK_CONDITION_CBOR(cn_cbor_array_append(pSigners, pSigner->m_message.m_cbor, &cbor_error), cbor_error);


	return true;

errorReturn:
	if (pSignersT == NULL) CN_CBOR_FREE(pSignersT, context);
	return false;
}

cn_cbor * COSE_Sign_map_get_int(HCOSE_SIGN h, int key, int flags, cose_errback * perror)
{
	if (!IsValidSignHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_SignMessage *)h)->m_message, key, flags, perror);
}

bool COSE_Sign_map_put(HCOSE_SIGN h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidSignHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_SignMessage *)h)->m_message, key, value, flags, perror);
}

