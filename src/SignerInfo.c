#include <stdlib.h>
#include <memory.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

extern bool IsValidSignHandle(HCOSE_SIGN h);

COSE * SignerRoot = NULL;

bool IsValidSignerHandle(HCOSE_SIGNER h)
{
	COSE_SignerInfo * p = (COSE_SignerInfo *)h;
	return _COSE_IsInList(SignerRoot, &p->m_message);
}


bool _COSE_SignerInfo_Free(COSE_SignerInfo * pSigner)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif

	//  Check ref counting
	if (pSigner->m_message.m_refCount > 1) {
		pSigner->m_message.m_refCount--;
		return true;
	}

#ifdef USE_CBOR_CONTEXT
	context = pSigner->m_message.m_allocContext;
#endif

	_COSE_Release(&pSigner->m_message);

	return true;
}

bool COSE_Signer_Free(HCOSE_SIGNER hSigner)
{
	COSE_SignerInfo * pSigner = (COSE_SignerInfo *)hSigner;

	if (!IsValidSignerHandle(hSigner))  return false;

	if (pSigner->m_message.m_refCount > 1) {
		pSigner->m_message.m_refCount--;
		return true;
	}

	_COSE_SignerInfo_Free(pSigner);

	_COSE_RemoveFromList(&SignerRoot, &pSigner->m_message);

	COSE_FREE(pSigner, &pSigner->m_message.m_allocContext);

	return true;
}


HCOSE_SIGNER COSE_Signer_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_SignerInfo * pobj = (COSE_SignerInfo *)COSE_CALLOC(1, sizeof(COSE_SignerInfo), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, COSE_recipient_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_SignerInfo_Free(pobj);
		COSE_FREE(pobj, context);
		return NULL;
	}

	_COSE_InsertInList(&SignerRoot, &pobj->m_message);
	return (HCOSE_SIGNER)pobj;
}



COSE_SignerInfo * _COSE_SignerInfo_Init_From_Object(cn_cbor * cbor, COSE_SignerInfo * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_SignerInfo * pSigner = pIn;

	if (pSigner == NULL) {
		pSigner = (COSE_SignerInfo *)COSE_CALLOC(1, sizeof(COSE_SignerInfo), context);
		CHECK_CONDITION(pSigner != NULL, COSE_ERR_OUT_OF_MEMORY);
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

	if (!_COSE_Init_From_Object(&pSigner->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_SignerInfo_Free(pSigner);
		if (pIn == NULL) COSE_FREE(pSigner, context);
		return NULL;
	}

	_COSE_InsertInList(&SignerRoot, &pSigner->m_message);
	return pSigner;

errorReturn:
	if (pSigner != NULL) COSE_FREE(pSigner, context);
	return NULL;
}

byte RgbDontUse4[1024];

bool BuildToBeSigned(byte ** ppbToSign, size_t * pcbToSign, const cn_cbor * pcborBody, const cn_cbor * pcborProtected, const cn_cbor * pcborProtectedSign, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	cn_cbor * pArray = NULL;
	cn_cbor_errback cbor_error;
	size_t cbToSign;
	byte * pbToSign = NULL;
	bool f = false;
	cn_cbor * cn = NULL;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(pArray != NULL, cbor_error);

	cn = cn_cbor_string_create("Signature", CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(pcborProtected->v.bytes, (int)pcborProtected->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(pcborProtectedSign->v.bytes, (int)pcborProtectedSign->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(pcborBody->v.bytes, (int)pcborBody->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
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
	f = true;
	
errorReturn:
	if (cn != NULL) CN_CBOR_FREE(cn, context);
	if (pArray != NULL) CN_CBOR_FREE(pArray, context);
	if (pbToSign != NULL) COSE_FREE(pbToSign, context);
	return f;

}


bool _COSE_Signer_sign(COSE_SignerInfo * pSigner, const cn_cbor * pcborBody, const cn_cbor * pcborProtected, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * pcborBody2 = NULL;
	cn_cbor * pcborProtected2 = NULL;
	cn_cbor * pcborProtectedSign = NULL;
	cn_cbor * pArray = NULL;
	cn_cbor * cnX = NULL;
	cn_cbor * cn = NULL;
	size_t cbToSign;
	byte * pbToSign = NULL;
	bool f;
	int alg;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	if (pArray == NULL) {
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (cn != NULL) CN_CBOR_FREE(cn, context);
		if (pcborBody2 != NULL) CN_CBOR_FREE(pcborBody2, context);
		if (pcborProtected2 != NULL) CN_CBOR_FREE(pcborProtected2, context);
		if (pArray != NULL) COSE_FREE(pArray, context);
		if (pbToSign != NULL) COSE_FREE(pbToSign, context);
		return false;
	}

	cnX = _COSE_map_get_int(&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cnX == NULL) goto errorReturn;

	if (cnX->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cnX->type == CN_CBOR_UINT || cnX->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cnX->v.uint;
	}

	pcborProtectedSign = _COSE_encode_protected(&pSigner->m_message, perr);
	if (pcborProtectedSign == NULL) goto errorReturn;

	if (!BuildToBeSigned(&pbToSign, &cbToSign, pcborBody, pcborProtected, pcborProtectedSign, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;

	switch (alg) {
	case COSE_Algorithm_ECDSA_SHA_256:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE, pSigner->m_pkey, 256, pbToSign, cbToSign, perr);
		break;

	case COSE_Algorithm_ECDSA_SHA_384:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE, pSigner->m_pkey, 384, pbToSign, cbToSign, perr);
		cn_cbor * cnProtected = _COSE_arrayget_int(&pSigner->m_message, INDEX_PROTECTED);
		CHECK_CONDITION((cnProtected != NULL) && (cnProtected->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);
		break;

	case COSE_Algorithm_ECDSA_SHA_512:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE, pSigner->m_pkey, 512, pbToSign, cbToSign, perr);
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	COSE_FREE(pbToSign, context);
	CN_CBOR_FREE(pArray, context);

	return f;
}

bool COSE_Signer_SetKey(HCOSE_SIGNER h, const cn_cbor * pKey, cose_errback * perror)
{
	COSE_SignerInfo * p;

	if (!IsValidSignerHandle(h) || (pKey == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	p = (COSE_SignerInfo *)h;
	p->m_pkey = pKey;

	return true;
}

byte RgbDontUseSign[8 * 1024];

bool _COSE_Signer_validate(COSE_SignMessage * pSign, COSE_SignerInfo * pSigner, const cn_cbor * pcborBody, const cn_cbor * pcborProtected, cose_errback * perr)
{
	byte * pbToBeSigned = NULL;
	int alg;
	const cn_cbor * cn = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	size_t cbToBeSigned;
	bool fRet = false;

#ifdef USE_CBOR_CONTEXT
	context = &pSign->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) goto errorReturn;

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}

	//  Build protected headers


	cn_cbor * cnProtected = _COSE_arrayget_int(&pSigner->m_message, INDEX_PROTECTED);
	CHECK_CONDITION((cnProtected != NULL) && (cnProtected->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

	//  Build authenticated data
	if (!BuildToBeSigned(&pbToBeSigned, &cbToBeSigned, pcborBody, pcborProtected, cnProtected, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;

	cn_cbor * cnSignature = _COSE_arrayget_int(&pSigner->m_message, INDEX_SIGNATURE);
	CHECK_CONDITION((cnSignature != NULL) && (cnSignature->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
	case COSE_Algorithm_ECDSA_SHA_256:
		if (!ECDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE, pSigner->m_pkey, 256, pbToBeSigned, cbToBeSigned, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_ECDSA_SHA_384:
		if (!ECDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE, pSigner->m_pkey, 384, pbToBeSigned, cbToBeSigned, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_ECDSA_SHA_512:
		if (!ECDSA_Verify(&pSigner->m_message, INDEX_SIGNATURE, pSigner->m_pkey, 512, pbToBeSigned, cbToBeSigned, perr)) goto errorReturn;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	fRet = true;

errorReturn:
	if (pbToBeSigned != NULL) COSE_FREE(pbToBeSigned, context);

	return fRet;
}

bool COSE_Signer_map_put(HCOSE_SIGNER h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidSignerHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_SignerInfo *)h)->m_message, key, value, flags, perror);
}
