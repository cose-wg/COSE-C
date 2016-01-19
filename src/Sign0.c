#include <stdlib.h>

#include "cose.h"
#include "cose_int.h"
#include "crypto.h"

bool _COSE_Signer0_sign(COSE_Sign0Message * pSigner, const cn_cbor * pKey, cose_errback * perr);
bool _COSE_Signer0_validate(COSE_Sign0Message * pSign, const cn_cbor * pKey, cose_errback * perr);
void _COSE_Sign0_Release(COSE_Sign0Message * p);

COSE * Sign0Root = NULL;

bool IsValidSign0Handle(HCOSE_SIGN0 h)
{
	COSE_Sign0Message * p = (COSE_Sign0Message *)h;

	if (p == NULL) return false;
	return _COSE_IsInList(Sign0Root, &p->m_message);
}


HCOSE_SIGN0 COSE_Sign0_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_Sign0Message * pobj = (COSE_Sign0Message *)COSE_CALLOC(1, sizeof(COSE_Sign0Message), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_Sign0_Release(pobj);
		COSE_FREE(pobj, context);
		return NULL;
	}

	_COSE_InsertInList(&Sign0Root, &pobj->m_message);

	return (HCOSE_SIGN0)pobj;
}

HCOSE_SIGN0 _COSE_Sign0_Init_From_Object(cn_cbor * cbor, COSE_Sign0Message * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_Sign0Message * pobj = pIn;
	cose_errback error = { 0 };

	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_Sign0Message *)COSE_CALLOC(1, sizeof(COSE_Sign0Message), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	if (pIn == NULL) _COSE_InsertInList(&Sign0Root, &pobj->m_message);

	return(HCOSE_SIGN0)pobj;

errorReturn:
	if (pobj != NULL) {
		_COSE_Sign0_Release(pobj);
		if (pIn == NULL) COSE_FREE(pobj, context);
	}
	return NULL;
}

bool COSE_Sign0_Free(HCOSE_SIGN0 h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif
	COSE_Sign0Message * pMessage = (COSE_Sign0Message *)h;

	if (!IsValidSign0Handle(h)) return false;

	//  Check reference counting
	if (pMessage->m_message.m_refCount > 1) {
		pMessage->m_message.m_refCount--;
		return true;
	}

	_COSE_RemoveFromList(&Sign0Root, &pMessage->m_message);

#ifdef USE_CBOR_CONTEXT
	context = pMessage->m_message.m_allocContext;
#endif

	_COSE_Sign0_Release(pMessage);

	COSE_FREE(pMessage, &context);

	return true;
}

void _COSE_Sign0_Release(COSE_Sign0Message * p)
{
	_COSE_Release(&p->m_message);
}

bool COSE_Sign0_SetContent(HCOSE_SIGN0 h, const byte * rgb, size_t cb, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	cn_cbor * p = NULL;
	COSE_Sign0Message * pMessage = (COSE_Sign0Message *)h;

	if (!IsValidSign0Handle(h) || (rgb == NULL)) {
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

bool COSE_Sign0_Sign(HCOSE_SIGN0 h, const cn_cbor * pKey, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	// cn_cbor_context * context = NULL;
#endif
	COSE_Sign0Message * pMessage = (COSE_Sign0Message *)h;
	const cn_cbor * pcborProtected;

	if (!IsValidSign0Handle(h)) {
		CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
	errorReturn:
		return false;
	}
#ifdef USE_CBOR_CONTEXT
	//	context = &pMessage->m_message.m_allocContext;
#endif

	pcborProtected = _COSE_encode_protected(&pMessage->m_message, perr);
	if (pcborProtected == NULL) goto errorReturn;

	if (!_COSE_Signer0_sign(pMessage, pKey, perr)) goto errorReturn;

	return true;
}

bool COSE_Sign0_validate(HCOSE_SIGN0 hSign, const cn_cbor * pKey, cose_errback * perr)
{
	bool f;
	COSE_Sign0Message * pSign;
	const cn_cbor * cnContent;
	const cn_cbor * cnProtected;

	CHECK_CONDITION(IsValidSign0Handle(hSign), COSE_ERR_INVALID_PARAMETER);

	pSign = (COSE_Sign0Message *)hSign;

	cnContent = _COSE_arrayget_int(&pSign->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	cnProtected = _COSE_arrayget_int(&pSign->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	f = _COSE_Signer0_validate(pSign, pKey,  perr);

	return f;

errorReturn:
	return false;
}


cn_cbor * COSE_Sign0_map_get_int(HCOSE_SIGN0 h, int key, int flags, cose_errback * perror)
{
	if (!IsValidSign0Handle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_Sign0Message *)h)->m_message, key, flags, perror);
}

bool COSE_Sign0_map_put_int(HCOSE_SIGN0 h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidSign0Handle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_Sign0Message *)h)->m_message, key, value, flags, perror);
}


byte RgbDontUse4[8 * 1024];
byte RgbDontUseSign[8 * 1024];

static bool CreateSign0AAD(COSE_Sign0Message * pMessage, byte ** ppbToSign, size_t * pcbToSign, char * szContext, cose_errback * perr)
{
	cn_cbor * pArray = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pMessage->m_message.m_allocContext;
#endif
	cn_cbor_errback cbor_error;
	cn_cbor * cn = NULL;
	cn_cbor * cn2;
	size_t cbToSign;
	byte * pbToSign = NULL;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(pArray != NULL, cbor_error);

	cn = cn_cbor_string_create(szContext, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn2 = _COSE_arrayget_int(&pMessage->m_message, INDEX_PROTECTED);

	cn = cn_cbor_data_create(cn2->v.bytes, (int)cn2->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn2 = _COSE_arrayget_int(&pMessage->m_message, INDEX_BODY);
	cn = cn_cbor_data_create(cn2->v.bytes, (int)cn2->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;


	cbToSign = cn_cbor_encoder_write(RgbDontUse4, 0, sizeof(RgbDontUse4), pArray);
	CHECK_CONDITION(cbToSign > 0, COSE_ERR_CBOR);
	pbToSign = (byte *)COSE_CALLOC(cbToSign, 1, context);
	CHECK_CONDITION(pbToSign != NULL, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(cn_cbor_encoder_write(pbToSign, 0, cbToSign, pArray), COSE_ERR_CBOR);

	*ppbToSign = pbToSign;
	*pcbToSign = cbToSign;
	pbToSign = NULL;

	if (cn != NULL) CN_CBOR_FREE(cn, context);
	if (pArray != NULL) COSE_FREE(pArray, context);
	return true;

errorReturn:
	if (pbToSign != NULL) COSE_FREE(pbToSign, context);
	if (cn != NULL) CN_CBOR_FREE(cn, context);
	if (pArray != NULL) COSE_FREE(pArray, context);
	return false;
}

bool _COSE_Signer0_sign(COSE_Sign0Message * pSigner, const cn_cbor * pKey, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * pcborBody2 = NULL;
	cn_cbor * pcborProtected2 = NULL;
	cn_cbor * pArray = NULL;
	cn_cbor * cn = NULL;
	size_t cbToSign;
	byte * pbToSign = NULL;
	bool f;
	int alg;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	if (pArray == NULL) {
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pcborBody2 != NULL) CN_CBOR_FREE(pcborBody2, context);
		if (pcborProtected2 != NULL) CN_CBOR_FREE(pcborProtected2, context);
		if (pArray != NULL) COSE_FREE(pArray, context);
		if (pbToSign != NULL) COSE_FREE(pbToSign, context);
		return false;
	}

	cn = _COSE_map_get_int(&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) goto errorReturn;

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}


	if (!CreateSign0AAD(pSigner, &pbToSign, &cbToSign, "Signature1", perr)) goto errorReturn;

	switch (alg) {
	case COSE_Algorithm_ECDSA_SHA_256:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE+1, pKey, 256, pbToSign, cbToSign, perr);
		break;

	case COSE_Algorithm_ECDSA_SHA_384:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE+1, pKey, 384, pbToSign, cbToSign, perr);
		break;

	case COSE_Algorithm_ECDSA_SHA_512:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE+1, pKey, 512, pbToSign, cbToSign, perr);
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	COSE_FREE(pbToSign, context);
	CN_CBOR_FREE(pArray, context);

	return f;
}

bool _COSE_Signer0_validate(COSE_Sign0Message * pSign, const cn_cbor * pKey, cose_errback * perr)
{
	byte * pbToSign = NULL;
	int alg;
	const cn_cbor * cn = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	size_t cbToSign;
	cn_cbor * cnSignature = NULL;
	bool fRet = false;

#ifdef USE_CBOR_CONTEXT
	context = &pSign->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pSign->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) goto errorReturn;

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}

	//  Build protected headers

	if (!CreateSign0AAD(pSign, &pbToSign, &cbToSign, "Signature1", perr)) goto errorReturn;

	cnSignature = _COSE_arrayget_int(&pSign->m_message, INDEX_SIGNATURE);

	switch (alg) {
	case COSE_Algorithm_ECDSA_SHA_256:
		if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE+1, pKey, 256, pbToSign, cbToSign, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_ECDSA_SHA_384:
		if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE+1, pKey, 384, pbToSign, cbToSign, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_ECDSA_SHA_512:
		if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE+1, pKey, 512, pbToSign, cbToSign, perr)) goto errorReturn;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	fRet = true;

errorReturn:
	if (pbToSign != NULL) COSE_FREE(pbToSign, context);

	return fRet;
}
