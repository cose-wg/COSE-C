#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <assert.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

void _COSE_Enveloped_Release(COSE_Enveloped * p);

byte RgbDontUse[8 * 1024];   //  Remove this array when we can compute the size of a cbor serialization without this hack.

COSE * EnvelopedRoot = NULL;

bool IsValidEnvelopedHandle(HCOSE_ENVELOPED h)
{
	COSE_Enveloped * p = (COSE_Enveloped *)h;
	return _COSE_IsInList(EnvelopedRoot, (COSE *) p);
}


size_t COSE_Encode(HCOSE msg, byte * rgb, size_t ib, size_t cb)
{
	if (rgb == NULL) return cn_cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), ((COSE *)msg)->m_cbor) + ib;
	return cn_cbor_encoder_write(rgb, ib, cb, ((COSE*)msg)->m_cbor);
}

HCOSE_ENVELOPED COSE_Enveloped_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_Enveloped * pobj = (COSE_Enveloped *)COSE_CALLOC(1, sizeof(COSE_Enveloped), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		_COSE_Enveloped_Release(pobj);
		COSE_FREE(pobj, context);
		return NULL;
	}

	_COSE_InsertInList(&EnvelopedRoot, &pobj->m_message);

	return (HCOSE_ENVELOPED) pobj;
}

HCOSE_ENVELOPED _COSE_Enveloped_Init_From_Object(cn_cbor * cbor, COSE_Enveloped * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_Enveloped * pobj = pIn;
	cn_cbor * pRecipients = NULL;
	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_Enveloped *)COSE_CALLOC(1, sizeof(COSE_Enveloped), context);
	if (pobj == NULL) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pobj != NULL) {
			_COSE_Enveloped_Release(pobj);
			if (pIn == NULL) COSE_FREE(pobj, context);
		}
		return NULL;
	}

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	pRecipients = _COSE_arrayget_int(&pobj->m_message, INDEX_RECIPIENTS);
	if (pRecipients != NULL) {
		CHECK_CONDITION(pRecipients->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

		pRecipients = pRecipients->first_child;
		while (pRecipients != NULL) {
			COSE_RecipientInfo * pInfo = _COSE_Recipient_Init_From_Object(pRecipients, CBOR_CONTEXT_PARAM_COMMA perr);
			CHECK_CONDITION(pInfo != NULL, COSE_ERR_OUT_OF_MEMORY);

			pInfo->m_recipientNext = pobj->m_recipientFirst;
			pobj->m_recipientFirst = pInfo;
			pRecipients = pRecipients->next;
		}
	}

	if (pIn == NULL) _COSE_InsertInList(&EnvelopedRoot, &pobj->m_message);

	return(HCOSE_ENVELOPED) pobj;
}

bool COSE_Enveloped_Free(HCOSE_ENVELOPED h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif
	COSE_Enveloped * p = (COSE_Enveloped *)h;

	if (!IsValidEnvelopedHandle(h)) return false;

#ifdef USE_CBOR_CONTEXT
	context = ((COSE_Enveloped *)h)->m_message.m_allocContext;
#endif

	_COSE_RemoveFromList(&EnvelopedRoot, &p->m_message);

	_COSE_Enveloped_Release((COSE_Enveloped *)h);

	COSE_FREE((COSE_Enveloped *)h, &context);

	return true;
}

void _COSE_Enveloped_Release(COSE_Enveloped * p)
{
	COSE_RecipientInfo * pRecipient1;
	COSE_RecipientInfo * pRecipient2;

	if (p->pbContent != NULL) COSE_FREE((void *) p->pbContent, &p->m_message.m_allocContext);
	//	if (p->pbIV != NULL) COSE_FREE(p->pbIV, &p->m_message.m_allocContext);

	for (pRecipient1 = p->m_recipientFirst; pRecipient1 != NULL; pRecipient1 = pRecipient2) {
		pRecipient2 = pRecipient1->m_recipientNext;
		COSE_Recipient_Free((HCOSE_RECIPIENT)pRecipient1);
	}

	_COSE_Release(&p->m_message);
}

bool COSE_Enveloped_decrypt(HCOSE_ENVELOPED h, HCOSE_RECIPIENT hRecip, cose_errback * perr)
{
	COSE_Enveloped * pcose = (COSE_Enveloped *)h;
	COSE_RecipientInfo * pRecip = (COSE_RecipientInfo *)hRecip;
	cose_errback error = { 0 };
	bool f;

	if (!IsValidEnvelopedHandle(h) || (!IsValidRecipientHandle(hRecip))) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	f = _COSE_Enveloped_decrypt(pcose, pRecip, 0, NULL, &error);
	if (perr != NULL) *perr = error;
	return f;
}

bool _COSE_Enveloped_decrypt(COSE_Enveloped * pcose, COSE_RecipientInfo * pRecip, int cbitKey, byte *pbKeyIn, cose_errback * perr)
{
	int alg;
	const cn_cbor * cn = NULL;

	byte * pbKey = pbKeyIn;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif
	byte * pbAuthData = NULL;
	size_t cbAuthData;
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
		if ((pbKey != NULL) && (pbKeyIn == NULL)) {
			memset(pbKey, 0xff, cbitKey / 8);
			COSE_FREE(pbKey, context);
		}
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

	//  Allocate the key if we have not already done so

	if (pbKey == NULL) {
		pbKey = COSE_CALLOC(cbitKey / 8, 1, context);
		CHECK_CONDITION(pbKey != NULL, COSE_ERR_OUT_OF_MEMORY);
	}

	//  If there is a recipient - ask it for the key

	for (pRecip = pcose->m_recipientFirst; pRecip != NULL; pRecip = pRecip->m_recipientNext) {
		if (_COSE_Recipient_decrypt(pRecip, alg, cbitKey, pbKey, perr)) break;
	}

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

	if (!_COSE_Encrypt_Build_AAD(&pcose->m_message, &pbAuthData, &cbAuthData, "Enveloped", perr)) goto errorReturn;

	cn = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION(cn != NULL, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
#ifdef INCLUDE_AES_CCM
	case COSE_Algorithm_AES_CCM_16_64_128:
	case COSE_Algorithm_AES_CCM_16_64_256:
		if (!AES_CCM_Decrypt(pcose, 64, 16, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	case COSE_Algorithm_AES_CCM_16_128_128:
	case COSE_Algorithm_AES_CCM_16_128_256:
		if (!AES_CCM_Decrypt(pcose, 128, 16, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	case COSE_Algorithm_AES_CCM_64_64_128:
	case COSE_Algorithm_AES_CCM_64_64_256:
		if (!AES_CCM_Decrypt(pcose, 64, 64, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	case COSE_Algorithm_AES_CCM_64_128_128:
	case COSE_Algorithm_AES_CCM_64_128_256:
		if (!AES_CCM_Decrypt(pcose, 128, 64, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;
#endif // INCLUDE_AES_CCM

	case COSE_Algorithm_AES_GCM_128:
	case COSE_Algorithm_AES_GCM_192:
	case COSE_Algorithm_AES_GCM_256:
		if (!AES_GCM_Decrypt(pcose, pbKey, cbitKey / 8, cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) goto error;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	if (pbProtected != NULL) COSE_FREE(pbProtected, context);
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if ((pbKey != NULL) && (pbKeyIn == NULL)) COSE_FREE(pbKey, context);
	if (perr != NULL) perr->err = COSE_ERR_NONE;

	return true;
}

bool COSE_Enveloped_encrypt(HCOSE_ENVELOPED h, cose_errback * perr)
{
	int alg;
	int t;
	COSE_RecipientInfo * pri;
	const cn_cbor * cn_Alg = NULL;
	byte * pbAuthData = NULL;
	size_t cbitKey;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	COSE_Enveloped * pcose = (COSE_Enveloped *) h;
	bool fRet = false;
	byte * pbKey = NULL;
	size_t cbKey = 0;

	CHECK_CONDITION(IsValidEnvelopedHandle(h), COSE_ERR_INVALID_PARAMETER);

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

	//  If we are doing direct encryption - then recipient generates the key

	if (pbKey == NULL) {
		t = 0;
		for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
			if (pri->m_encrypt.m_message.m_flags & 1) {
				t |= 1;
				pbKey = _COSE_RecipientInfo_generateKey(pri, alg, cbitKey, perr);
				cbKey = cbitKey / 8;
				if (pbKey == NULL) goto errorReturn;
			}
			else {
				t |= 2;
			}
		}
		CHECK_CONDITION(t != 3, COSE_ERR_INVALID_PARAMETER);
	}

	if (pbKey == NULL) {
		pbKey = (byte *) COSE_CALLOC(cbitKey/8, 1, context);
		CHECK_CONDITION(pbKey != NULL, COSE_ERR_OUT_OF_MEMORY);
		cbKey = cbitKey / 8;
		rand_bytes(pbKey, cbKey);
	}

	//  Build protected headers

	const cn_cbor * cbProtected = _COSE_encode_protected(&pcose->m_message, perr);
	if (cbProtected == NULL) goto errorReturn;

	//  Build authenticated data

	size_t cbAuthData = 0;
	if (!_COSE_Encrypt_Build_AAD(&pcose->m_message, &pbAuthData, &cbAuthData, "Enveloped", perr)) goto errorReturn;

	switch (alg) {
#ifdef INCLUDE_AES_CCM
	case COSE_Algorithm_AES_CCM_16_64_128:
	case COSE_Algorithm_AES_CCM_16_64_256:
		if (!AES_CCM_Encrypt(pcose, 64, 16, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_AES_CCM_16_128_128:
	case COSE_Algorithm_AES_CCM_16_128_256:
		if (!AES_CCM_Encrypt(pcose, 128, 16, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_AES_CCM_64_64_128:
	case COSE_Algorithm_AES_CCM_64_64_256:
		if (!AES_CCM_Encrypt(pcose, 64, 64, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Algorithm_AES_CCM_64_128_128:
	case COSE_Algorithm_AES_CCM_64_128_256:
		if (!AES_CCM_Encrypt(pcose, 128, 64, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;
#endif

	case COSE_Algorithm_AES_GCM_128:
	case COSE_Algorithm_AES_GCM_192:
	case COSE_Algorithm_AES_GCM_256:
		if (!AES_GCM_Encrypt(pcose, pbKey, cbKey, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
		if (!_COSE_Recipient_encrypt(pri, pbKey, cbKey, perr)) goto errorReturn;
	}

	//  Figure out the clean up

	fRet = true;

errorReturn:
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pbKey != NULL) {
		memset(pbKey, 0, cbKey);
		COSE_FREE(pbKey, context);
	}
	return fRet;
}

bool COSE_Enveloped_SetContent(HCOSE_ENVELOPED h, const byte * rgb, size_t cb, cose_errback * perror)
{
	if (!IsValidEnvelopedHandle(h) || (rgb == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_Enveloped_SetContent((COSE_Enveloped *)h, rgb, cb, perror);
}

bool COSE_Enveloped_SetExternal(HCOSE_ENVELOPED hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr)
{
	if (!IsValidEnvelopedHandle(hcose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_SetExternal(&((COSE_Enveloped *)hcose)->m_message, pbExternalData, cbExternalData, perr);
}


bool _COSE_Enveloped_SetContent(COSE_Enveloped * cose, const byte * rgb, size_t cb, cose_errback * perror)
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

cn_cbor * COSE_Enveloped_map_get_int(HCOSE_ENVELOPED h, int key, int flags, cose_errback * perror)
{
	if (!IsValidEnvelopedHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_Enveloped *)h)->m_message, key, flags, perror);
}


bool COSE_Enveloped_map_put_int(HCOSE_ENVELOPED h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidEnvelopedHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_Enveloped *)h)->m_message, key, value, flags, perror);
}

bool COSE_Enveloped_AddRecipient(HCOSE_ENVELOPED hEnc, HCOSE_RECIPIENT hRecip, cose_errback * perr)
{
	COSE_RecipientInfo * pRecip;
	COSE_Enveloped * pEncrypt;
	cn_cbor * pRecipients  = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidEnvelopedHandle(hEnc), COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(IsValidRecipientHandle(hRecip), COSE_ERR_INVALID_PARAMETER);

	pEncrypt = (COSE_Enveloped *)hEnc;
	pRecip = (COSE_RecipientInfo *)hRecip;

#ifdef USE_CBOR_CONTEXT
	context = &pEncrypt->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	pRecip->m_recipientNext = pEncrypt->m_recipientFirst;
	pEncrypt->m_recipientFirst = pRecip;

	pRecipients = _COSE_arrayget_int(&pEncrypt->m_message, INDEX_RECIPIENTS);
	if (pRecipients == NULL) {
		pRecipients = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(pRecipients != NULL, cbor_error);

		if (!_COSE_array_replace(&pEncrypt->m_message, pRecipients, INDEX_RECIPIENTS, CBOR_CONTEXT_PARAM_COMMA &cbor_error)) {
			CN_CBOR_FREE(pRecipients, context);
			if (perr != NULL) perr->err = _MapFromCBOR(cbor_error);
			goto errorReturn;
		}
	}

	CHECK_CONDITION_CBOR(cn_cbor_array_append(pRecipients, pRecip->m_encrypt.m_message.m_cbor, &cbor_error), cbor_error);

	pRecip->m_encrypt.m_message.m_refCount++;

	return true;

errorReturn:
	return false;
}

bool _COSE_Encrypt_Build_AAD(COSE * pMessage, byte ** ppbAAD, size_t * pcbAAD, const char * szContext, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pMessage->m_allocContext;
#endif
	cn_cbor_errback cbor_error;
	byte  * pbAuthData;
	size_t cbAuthData;
	cn_cbor * pAuthData;
	cn_cbor * pItem;
	cn_cbor * ptmp = NULL;

	//  Build authenticated data
	pbAuthData = NULL;
	pAuthData = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(pAuthData != NULL, cbor_error);

	ptmp = cn_cbor_string_create(szContext, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = NULL;

	pItem = _COSE_arrayget_int(pMessage, INDEX_PROTECTED);
	CHECK_CONDITION(pItem != NULL, COSE_ERR_INVALID_PARAMETER);
	if ((pItem->length == 1) && (pItem->v.bytes[0] == 0xa0)) {
		ptmp = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	}
	else {
		ptmp = cn_cbor_data_create(pItem->v.bytes, (int)pItem->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	}
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = NULL;

	ptmp = cn_cbor_data_create(pMessage->m_pbExternal, (int) pMessage->m_cbExternal, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = NULL;

	cbAuthData = cn_cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), pAuthData);
	pbAuthData = (byte *)COSE_CALLOC(cbAuthData, 1, context);
	CHECK_CONDITION(pbAuthData != NULL, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION((size_t)cn_cbor_encoder_write(pbAuthData, 0, cbAuthData, pAuthData) == cbAuthData, COSE_ERR_CBOR);

	*ppbAAD = pbAuthData;
	*pcbAAD = cbAuthData;

	return true;

errorReturn:
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (ptmp != NULL) CN_CBOR_FREE(ptmp, NULL);
	if (pAuthData != NULL) CN_CBOR_FREE(pAuthData, context);
	return false;
}

HCOSE_RECIPIENT COSE_Enveloped_GetRecipient(HCOSE_ENVELOPED cose, int iRecipient, cose_errback * perr)
{
	int i;
	COSE_RecipientInfo * p = NULL;

	CHECK_CONDITION(IsValidEnvelopedHandle(cose), COSE_ERR_INVALID_PARAMETER);

	p = ((COSE_Enveloped *)cose)->m_recipientFirst;
	for (i = 0; i < iRecipient; i++) {
		CHECK_CONDITION(p != NULL, COSE_ERR_INVALID_PARAMETER);
		p = p->m_recipientNext;
	}
	if (p != NULL) p->m_encrypt.m_message.m_refCount++;

errorReturn:
	return (HCOSE_RECIPIENT)p;
}
