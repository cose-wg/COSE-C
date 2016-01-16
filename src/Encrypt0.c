#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <assert.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

byte RgbDontUse[8 * 1024];   //  Remove this array when we can compute the size of a cbor serialization without this hack.

void _COSE_Encrypt_Release(COSE_Encrypt * p);

COSE * EncryptRoot = NULL;


bool IsValidEncryptHandle(HCOSE_ENCRYPT h)
{
	COSE_Encrypt * p = (COSE_Encrypt *)h;
	return _COSE_IsInList(EncryptRoot, &p->m_message);
}


HCOSE_ENCRYPT COSE_Encrypt_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_Encrypt * pobj = (COSE_Encrypt *)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_Encrypt_Release(pobj);
		COSE_FREE(pobj, context);
		return NULL;
	}

	_COSE_InsertInList(&EncryptRoot, &pobj->m_message);

	return (HCOSE_ENCRYPT) pobj;
}

HCOSE_ENCRYPT _COSE_Encrypt_Init_From_Object(cn_cbor * cbor, COSE_Encrypt * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_Encrypt * pobj = pIn;
	cn_cbor * pRecipients = NULL;
	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_Encrypt *)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	if (pobj == NULL) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pobj != NULL) {
			_COSE_Encrypt_Release(pobj);
			if (pIn == NULL)  COSE_FREE(pobj, context);
		}
		return NULL;
	}

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	pRecipients = _COSE_arrayget_int(&pobj->m_message, INDEX_RECIPIENTS);
	CHECK_CONDITION(pRecipients == NULL, COSE_ERR_INVALID_PARAMETER);

	_COSE_InsertInList(&EncryptRoot, &pobj->m_message);

	return(HCOSE_ENCRYPT) pobj;
}

bool COSE_Encrypt_Free(HCOSE_ENCRYPT h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif
	COSE_Encrypt * pEncrypt = (COSE_Encrypt *)h;

	if (!IsValidEncryptHandle(h)) return false;

#ifdef USE_CBOR_CONTEXT
	context = ((COSE_Encrypt *)h)->m_message.m_allocContext;
#endif

	_COSE_Encrypt_Release(pEncrypt);

	_COSE_RemoveFromList(&EncryptRoot, &pEncrypt->m_message);
	
	COSE_FREE((COSE_Encrypt *)h, &context);

	return true;
}

void _COSE_Encrypt_Release(COSE_Encrypt * p)
{
	if (p->pbContent != NULL) COSE_FREE((void *) p->pbContent, &p->m_message.m_allocContext);
	//	if (p->pbIV != NULL) COSE_FREE(p->pbIV, &p->m_message.m_allocContext);
	if (p->pbKey != NULL) COSE_FREE(p ->pbKey, &p->m_message.m_allocContext);

	_COSE_Release(&p->m_message);
}

bool COSE_Encrypt_decrypt(HCOSE_ENCRYPT h, const byte * pbKey, size_t cbKey, cose_errback * perr)
{
	COSE_Encrypt * pcose = (COSE_Encrypt *)h;
	cose_errback error = { 0 };
	bool f;

	if (!IsValidEncryptHandle(h)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	f = _COSE_Encrypt_decrypt(pcose, pbKey, cbKey, &error);
	if (perr != NULL) *perr = error;
	return f;
}

bool _COSE_Encrypt_decrypt(COSE_Encrypt * pcose, const byte * pbKey, size_t cbKey, cose_errback * perr)
{
	int alg;
	const cn_cbor * cn = NULL;
	int cbitKey;

#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif
	byte * pbAuthData = NULL;
	size_t cbAuthData;
	cn_cbor * pAuthData = NULL;
	byte * pbProtected = NULL;
	ssize_t cbProtected;

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) {
	error:
	errorReturn:
		if (pbProtected != NULL) COSE_FREE(pbProtected, context);
		if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
		if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
		return false;
	}
	CHECK_CONDITION((cn->type == CN_CBOR_UINT) || (cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);
	alg = (int) cn->v.uint;

	switch (alg) {
#ifdef INCLUDE_AES_CCM
	case COSE_Algorithm_AES_CCM_16_64_128:
	case COSE_Algorithm_AES_CCM_16_128_128:
	case COSE_Algorithm_AES_CCM_64_64_128:
	case COSE_Algorithm_AES_CCM_64_128_128:
		cbitKey = 128;
		break;

	case COSE_Algorithm_AES_CCM_64_64_256:
	case COSE_Algorithm_AES_CCM_16_128_256:
	case COSE_Algorithm_AES_CCM_64_128_256:
	case COSE_Algorithm_AES_CCM_16_64_256:
		cbitKey = 256;
		break;
#endif // INCLUDE_AES_CCM

	case COSE_Algorithm_AES_GCM_128:
		cbitKey = 128;
		break;

	case COSE_Algorithm_AES_GCM_192:
		cbitKey = 192;
		break;

	case COSE_Algorithm_AES_GCM_256:
		cbitKey = 256;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	CHECK_CONDITION(cbitKey / 8 == cbKey, COSE_ERR_INVALID_PARAMETER);

	//  Build protected headers

	CHECK_CONDITION(pcose->m_message.m_protectedMap != NULL, COSE_ERR_INVALID_PARAMETER);
	if ((pcose->m_message.m_protectedMap != NULL) && (pcose->m_message.m_protectedMap->first_child != NULL)) {
		cbProtected = cn_cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), pcose->m_message.m_protectedMap);
		pbProtected = (byte *)COSE_CALLOC(cbProtected, 1, context);
		if (pbProtected == NULL) goto error;
		if (cn_cbor_encoder_write(pbProtected, 0, cbProtected, pcose->m_message.m_protectedMap) != cbProtected) goto error;
	}
	else {
		pbProtected = NULL;
		cbProtected = 0;
	}

	//  Build authenticated data
	if (!_COSE_Encrypt_Build_AAD(&pcose->m_message, &pbAuthData, &cbAuthData, "Encrypted", perr)) goto errorReturn;

	cn = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION(cn != NULL, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
#ifdef INCLUDE_AES_CCM
	case COSE_Algorithm_AES_CCM_16_64_128:
	case COSE_Algorithm_AES_CCM_16_64_256:
		if (!AES_CCM_Decrypt((COSE_Enveloped *)pcose, 64, 16, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	case COSE_Algorithm_AES_CCM_16_128_128:
	case COSE_Algorithm_AES_CCM_16_128_256:
		if (!AES_CCM_Decrypt((COSE_Enveloped *)pcose, 128, 16, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	case COSE_Algorithm_AES_CCM_64_64_128:
	case COSE_Algorithm_AES_CCM_64_64_256:
		if (!AES_CCM_Decrypt((COSE_Enveloped *)pcose, 64, 64, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	case COSE_Algorithm_AES_CCM_64_128_128:
	case COSE_Algorithm_AES_CCM_64_128_256:
		if (!AES_CCM_Decrypt((COSE_Enveloped *)pcose, 128, 64, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;
#endif // INCLUDE_AES_CCM

	case COSE_Algorithm_AES_GCM_128:
	case COSE_Algorithm_AES_GCM_192:
	case COSE_Algorithm_AES_GCM_256:
		if (!AES_GCM_Decrypt((COSE_Enveloped *)pcose, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	if (pbProtected != NULL) COSE_FREE(pbProtected, context);
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
	if (perr != NULL) perr->err = COSE_ERR_NONE;

	return true;
}

bool COSE_Encrypt_encrypt(HCOSE_ENCRYPT h, const byte * pbKey, size_t cbKey, cose_errback * perr)
{
	int alg;
	const cn_cbor * cn_Alg = NULL;
	byte * pbAuthData = NULL;
	cn_cbor * pAuthData = NULL;
	cn_cbor * ptmp = NULL;
	size_t cbitKey;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	COSE_Encrypt * pcose = (COSE_Encrypt *) h;

	CHECK_CONDITION(IsValidEncryptHandle(h), COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	cn_Alg = _COSE_map_get_int(&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn_Alg == NULL) goto errorReturn;

	CHECK_CONDITION((cn_Alg->type == CN_CBOR_UINT) || (cn_Alg->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);
	alg = (int) cn_Alg->v.uint;

	//  Get the key size

	switch (alg) {
#ifdef INCLUDE_AES_CCM
	case COSE_Algorithm_AES_CCM_64_64_128:
	case COSE_Algorithm_AES_CCM_16_128_128:
	case COSE_Algorithm_AES_CCM_64_128_128:
	case COSE_Algorithm_AES_CCM_16_64_128:
		cbitKey = 128;
		break;

	case COSE_Algorithm_AES_CCM_64_64_256:
	case COSE_Algorithm_AES_CCM_16_128_256:
	case COSE_Algorithm_AES_CCM_64_128_256:
	case COSE_Algorithm_AES_CCM_16_64_256:
		cbitKey = 256;
		break;
#endif // INCLUDE_AES_CCM

	case COSE_Algorithm_AES_GCM_128: cbitKey = 128; break;
	case COSE_Algorithm_AES_GCM_192: cbitKey = 192; break;
	case COSE_Algorithm_AES_GCM_256: cbitKey = 256; break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	//  Build protected headers

	const cn_cbor * cbProtected = _COSE_encode_protected(&pcose->m_message, perr);
	if (cbProtected == NULL) goto errorReturn;

	//  Build authenticated data
	size_t cbAuthData = 0;

	if (!_COSE_Encrypt_Build_AAD(&pcose->m_message, &pbAuthData, &cbAuthData, "Encrypted", perr)) goto errorReturn;

	switch (alg) {
#ifdef INCLUDE_AES_CCM
	case COSE_Algorithm_AES_CCM_16_64_128:
	case COSE_Algorithm_AES_CCM_16_64_256:
		if (!AES_CCM_Encrypt((COSE_Enveloped *)pcose, 64, 16, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_AES_CCM_16_128_128:
	case COSE_Algorithm_AES_CCM_16_128_256:
		if (!AES_CCM_Encrypt((COSE_Enveloped *)pcose, 128, 16, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_AES_CCM_64_64_128:
	case COSE_Algorithm_AES_CCM_64_64_256:
		if (!AES_CCM_Encrypt((COSE_Enveloped *)pcose, 64, 64, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_AES_CCM_64_128_128:
	case COSE_Algorithm_AES_CCM_64_128_256:
		if (!AES_CCM_Encrypt((COSE_Enveloped *)pcose, 128, 64, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;
#endif

	case COSE_Algorithm_AES_GCM_128:
	case COSE_Algorithm_AES_GCM_192:
	case COSE_Algorithm_AES_GCM_256:
		if (!AES_GCM_Encrypt((COSE_Enveloped *)pcose, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	//  Figure out the clean up

	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);

	return true;

errorReturn:
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
	if (ptmp != NULL) cn_cbor_free(ptmp CBOR_CONTEXT_PARAM);
	return false;
}

bool COSE_Encrypt_SetContent(HCOSE_ENCRYPT h, const byte * rgb, size_t cb, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h) || (rgb == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_Encrypt_SetContent((COSE_Encrypt *)h, rgb, cb, perror);
}

bool _COSE_Encrypt_SetContent(COSE_Encrypt * cose, const byte * rgb, size_t cb, cose_errback * perror)
{
	byte * pb;
	cose->pbContent = pb = (byte *)COSE_CALLOC(cb, 1, &cose->m_message.m_allocContext);
	if (cose->pbContent == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}
	memcpy(pb, rgb, cb);
	cose->cbContent = cb;

	return true;
}

cn_cbor * COSE_Encrypt_map_get_int(HCOSE_ENCRYPT h, int key, int flags, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_Encrypt *)h)->m_message, key, flags, perror);
}


bool COSE_Encrypt_map_put_int(HCOSE_ENCRYPT h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_Encrypt *)h)->m_message, key, value, flags, perror);
}
