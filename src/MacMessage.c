#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

byte RgbDontUse2[8 * 1024];   //  Remove this array when we can compute the size of a cbor serialization without this hack.


bool IsValidMacHandle(HCOSE_MAC h)
{
	COSE_MacMessage * p = (COSE_MacMessage *)h;
	if (p == NULL) return false;
	return true;
}


HCOSE_MAC COSE_Mac_Init(CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_MacMessage * pobj = (COSE_MacMessage *)COSE_CALLOC(1, sizeof(COSE_MacMessage), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(&pobj->m_message, COSE_mac_object, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	return (HCOSE_MAC)pobj;

errorReturn:
	if (pobj != NULL) COSE_Mac_Free((HCOSE_MAC)pobj);
	return NULL;
}

HCOSE_MAC _COSE_Mac_Init_From_Object(cn_cbor * cbor, COSE_MacMessage * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_MacMessage * pobj = pIn;
	cn_cbor * pRecipients = NULL;
	// cn_cbor * tmp;
	cose_errback error = { COSE_ERR_NONE };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_MacMessage *)COSE_CALLOC(1, sizeof(COSE_MacMessage), context);
	if (pobj == NULL) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if ((pIn == NULL) && (pobj != NULL)) COSE_FREE(pobj, context);
		return NULL;
	}

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

#ifdef USE_ARRAY
	pRecipients = _COSE_arrayget_int(&pobj->m_message, INDEX_MAC_RECIPIENTS);
#else
	pRecipients = (cn_cbor *)cn_cbor_mapget_int(cbor, COSE_Header_Recipients);
#endif
	if (pRecipients != NULL) {
		CHECK_CONDITION(pRecipients->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

		pRecipients = pRecipients->first_child;
		while (pRecipients != NULL) {
			COSE_RecipientInfo * pInfo = _COSE_Recipient_Init_From_Object(pRecipients, CBOR_CONTEXT_PARAM_COMMA perr);
			if (pInfo == NULL) goto errorReturn;

			pInfo->m_recipientNext = pobj->m_recipientFirst;
			pobj->m_recipientFirst = pInfo;
			pRecipients = pRecipients->next;
		}
	}

	return(HCOSE_MAC)pobj;
}

bool COSE_Mac_Free(HCOSE_MAC h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif

	if (!IsValidMacHandle(h)) return false;

#ifdef USE_CBOR_CONTEXT
	context = ((COSE_MacMessage *)h)->m_message.m_allocContext;
#endif

	_COSE_Mac_Release((COSE_MacMessage *)h);

	COSE_FREE((COSE_MacMessage *)h, &context);

	return true;
}

void _COSE_Mac_Release(COSE_MacMessage * p)
{
	if (p->pbKey != NULL) COSE_FREE(p->pbKey, &p->m_message.m_allocContext);

	_COSE_Release(&p->m_message);
}


HCOSE_RECIPIENT COSE_Mac_add_shared_secret(HCOSE_MAC hcose, COSE_Algorithms alg, byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif // USE_CBOR_CONTEXT

	COSE_RecipientInfo * pobj;
	COSE_MacMessage * pcose = (COSE_MacMessage *)hcose;
	cn_cbor * cn_Temp = NULL;
	cn_cbor * pRecipients = NULL;
	cn_cbor * pRecipientsNew = NULL;
	byte * pbKey = NULL;
	byte * pbTemp = NULL;
	cn_cbor * cnTemp = NULL;
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidMacHandle(hcose) && (rgbKey != NULL), COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	switch (alg) {
	case COSE_Algorithm_Direct:
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	pobj = (COSE_RecipientInfo *)COSE_CALLOC(1, sizeof(COSE_RecipientInfo), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(&pobj->m_encrypt.m_message, COSE_unknown_object, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	cn_Temp = cn_cbor_int_create(alg, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn_Temp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pobj->m_encrypt.m_message.m_unprotectMap, COSE_Header_Algorithm, cn_Temp, CBOR_CONTEXT_PARAM_COMMA &cbor_error), cbor_error);
	cn_Temp = NULL;

	if (cbKid > 0) {
		pbTemp = (byte *)COSE_CALLOC(cbKid, 1, context);
		CHECK_CONDITION(pbTemp != NULL, COSE_ERR_OUT_OF_MEMORY);

		memcpy(pbTemp, rgbKid, cbKid);
		cnTemp = cn_cbor_data_create(pbTemp, cbKid, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(cnTemp != NULL, cbor_error);
		pbTemp = NULL;

		CHECK_CONDITION_CBOR(cn_cbor_mapput_int(pobj->m_encrypt.m_message.m_unprotectMap, COSE_Header_KID, cnTemp, CBOR_CONTEXT_PARAM_COMMA &cbor_error), cbor_error);
	}

	pobj->m_encrypt.pbKey = pbKey = (byte *)COSE_CALLOC(cbKey, 1, context);
	CHECK_CONDITION(pobj->m_encrypt.pbKey != NULL, COSE_ERR_OUT_OF_MEMORY);

	memcpy(pbKey, rgbKey, cbKey);
	pobj->m_encrypt.cbKey = cbKey;

	pobj->m_recipientNext = pcose->m_recipientFirst;
	pcose->m_recipientFirst = pobj;

#ifdef USE_ARRAY
	pRecipients = _COSE_arrayget_int(&pcose->m_message, INDEX_MAC_RECIPIENTS);
#else
	cn_cbor * pRecipients = (cn_cbor *)cn_cbor_mapget_int(pcose->m_message.m_cbor, COSE_Header_Recipients);
#endif
	if (pRecipients == NULL) {
		pRecipients = pRecipientsNew = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(pRecipients != NULL, cbor_error);
		pRecipientsNew = NULL;

#ifdef USE_ARRAY
		CHECK_CONDITION_CBOR(_COSE_array_replace(&pcose->m_message, pRecipients, INDEX_MAC_RECIPIENTS, CBOR_CONTEXT_PARAM_COMMA &cbor_error), cbor_error);
#else
		if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Recipients, pRecipients, CBOR_CONTEXT_PARAM_COMMA NULL)) {
			cn_cbor_free(pRecipients, context);
			goto error;
		}
#endif
	}

	CHECK_CONDITION_CBOR(cn_cbor_array_append(pRecipients, pobj->m_encrypt.m_message.m_cbor, &cbor_error), cbor_error);

	pobj->m_encrypt.m_message.m_flags |= 1;
	return (HCOSE_RECIPIENT)pobj;

errorReturn:
	if (cn_Temp != NULL) CN_CBOR_FREE(cn_Temp, context);
	if (pRecipientsNew != NULL) CN_CBOR_FREE(pRecipientsNew, context);
	// if (pobj != NULL) COSE_Recipient_Free(pobj);
	return NULL;
}

bool COSE_Mac_SetContent(HCOSE_MAC cose, const byte * rgbContent, size_t cbContent, cose_errback * perr)
{
	COSE_MacMessage * p = (COSE_MacMessage *)cose;
#ifdef USE_CBOR_CONTEXT        
	cn_cbor_context * context = &p->m_message.m_allocContext;
#endif
	cn_cbor * ptmp = NULL;
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidMacHandle(cose), COSE_ERR_INVALID_PARAMETER);

	ptmp = cn_cbor_data_create(rgbContent, (int) cbContent, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);

#ifdef USE_ARRAY
	CHECK_CONDITION_CBOR(_COSE_array_replace(&p->m_message, ptmp, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA &cbor_error),  cbor_error);
	ptmp = NULL;
#else
	if (!cn_cbor_mapput_int(p->m_message.m_cbor, COSE_Header_PlainText, cn_cbor_data_create (rgbContent, cbContent, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		if (errp != NULL) errp->err = COSE_ERR_CBOR;
		return;
	}
#endif
	return true;

errorReturn:
	if (ptmp != NULL) CN_CBOR_FREE(ptmp, context);
	return false;
}


cn_cbor * COSE_Mac_map_get_int(HCOSE_MAC h, int key, int flags, cose_errback * perror)
{
	if (!IsValidMacHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_MacMessage *)h)->m_message, key, flags, perror);
}


bool COSE_Mac_map_put(HCOSE_MAC h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidMacHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_MacMessage *)h)->m_message, key, value, flags, perror);
}


bool COSE_Mac_encrypt(HCOSE_MAC h, cose_errback * perr)
{
	int alg;
	int t;
	COSE_RecipientInfo * pri;
	const cn_cbor * cn_Alg = NULL;
	byte * pbAuthData = NULL;
	cn_cbor * pAuthData = NULL;
	cn_cbor * ptmp = NULL;
	size_t cbitKey;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	COSE_MacMessage * pcose = (COSE_MacMessage *)h;
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidMacHandle(h), COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	cn_Alg = _COSE_map_get_int(&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn_Alg == NULL) goto errorReturn;
	CHECK_CONDITION(((cn_Alg->type == CN_CBOR_UINT || cn_Alg->type == CN_CBOR_INT)), COSE_ERR_INVALID_PARAMETER);

	alg = (int) cn_Alg->v.uint;

	//  Get the key size

	switch (alg) {
	case COSE_Algorithm_HMAC_256_256:
		cbitKey = 256;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	//  If we are doing direct encryption - then recipient generates the key

	if (pcose->pbKey == NULL) {
		t = 0;
		for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
			if (pri->m_encrypt.m_message.m_flags & 1) {
				t |= 1;
				pcose->pbKey = _COSE_RecipientInfo_generateKey(pri, cbitKey, perr);
				if (pcose->pbKey == NULL) goto errorReturn;

				pcose->cbKey = cbitKey / 8;
			}
			else {
				t |= 2;
			}
		}
		CHECK_CONDITION(t != 3, COSE_ERR_INVALID_PARAMETER);
	}

	if (pcose->pbKey == NULL) {
		pcose->pbKey = (byte *)COSE_CALLOC(cbitKey / 8, 1, context);
		CHECK_CONDITION(pcose->pbKey != NULL, COSE_ERR_OUT_OF_MEMORY);

		pcose->cbKey = cbitKey / 8;
		rand_bytes(pcose->pbKey, pcose->cbKey);
	}

	//  Build protected headers

	const cn_cbor * cbProtected = _COSE_encode_protected(&pcose->m_message, perr);
	if (cbProtected == NULL) goto errorReturn;

	//  Get the body
	const cn_cbor * cbBody = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION(cbBody != NULL, COSE_ERR_INVALID_PARAMETER);

#ifndef USE_ARRAY
	//  Add Unprotected headers

	if (pcose->m_message.m_unprotectMap->first_child != NULL) {
		if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Unprotected, pcose->m_message.m_unprotectMap, CBOR_CONTEXT_PARAM_COMMA NULL)) goto error;
		pcose->m_message.m_ownUnprotectedMap = false;
	}
#endif

	//  Build authenticated data
	//  Protected headers
	//  external data
	//  body

	ssize_t cbAuthData = 0;
	pAuthData = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pAuthData != NULL, COSE_ERR_OUT_OF_MEMORY);

	ptmp = cn_cbor_data_create(cbProtected->v.bytes, (int) cbProtected->length, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(ptmp != NULL, COSE_ERR_CBOR);

	CHECK_CONDITION(cn_cbor_array_append(pAuthData, ptmp, NULL), COSE_ERR_CBOR);
	ptmp = NULL;

	ptmp = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = NULL;

	ptmp = cn_cbor_data_create(cbBody->v.bytes, (int) cbBody->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = NULL;

	cbAuthData = cn_cbor_encoder_write(RgbDontUse2, 0, sizeof(RgbDontUse2), pAuthData);
	CHECK_CONDITION(cbAuthData > 0, COSE_ERR_CBOR);
	pbAuthData = (byte *)COSE_CALLOC(cbAuthData, 1, context);
	CHECK_CONDITION(pbAuthData != NULL, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(cn_cbor_encoder_write(pbAuthData, 0, cbAuthData, pAuthData) == cbAuthData, COSE_ERR_CBOR);

	switch (alg) {
	case COSE_Algorithm_HMAC_256_256:
		if (!HMAC_Create(pcose, 256, 256, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	default:
		return false;
	}

	for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
		if (!_COSE_Encrypt_SetContent(&pri->m_encrypt, pcose->pbKey, pcose->cbKey, perr)) goto errorReturn;

		if (!COSE_Encrypt_encrypt((HCOSE_ENCRYPT)&pri->m_encrypt, perr)) goto errorReturn;
	}

	//  Figure out the clean up

	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
	if (ptmp != NULL) cn_cbor_free(ptmp CBOR_CONTEXT_PARAM);
	return true;

errorReturn:
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
	if (ptmp != NULL) cn_cbor_free(ptmp CBOR_CONTEXT_PARAM);
	return false;
}

byte RgbDontUseMac[1024];

bool COSE_Mac_validate(HCOSE_MAC h, HCOSE_RECIPIENT hRecip, cose_errback * perr)
{
	COSE_MacMessage * pcose = (COSE_MacMessage *)h;
	COSE_RecipientInfo * pRecip = (COSE_RecipientInfo *)hRecip;
	cn_cbor_errback cbor_error;
	byte * pbAuthData = NULL;
	int cbitKey = 0;
	byte * pbKeyIn = NULL;

	int alg;
	const cn_cbor * cn = NULL;

	byte * pbKey = pbKeyIn;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	ssize_t cbAuthData;
	cn_cbor * pAuthData = NULL;
	cn_cbor * ptmp = NULL;

	CHECK_CONDITION(IsValidMacHandle(h) && IsValidRecipientHandle(hRecip), COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) goto errorReturn;

	if (cn->type == CN_CBOR_TEXT) {
		if (cn->length == 15) {
			if (strncmp(cn->v.str, "AES-CMAC-256/64", 15) == 0) {
				cbitKey = 256;
				alg = COSE_Int_Alg_AES_CMAC_256_64;
			}
			else {
				FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			}
		}
		else {
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		}
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;

		switch (alg) {
		case COSE_Algorithm_HMAC_256_256:
			cbitKey = 256;
			break;

		case COSE_Int_Alg_AES_CMAC_256_64:
		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			break;
		}
	}

	//  Allocate the key if we have not already done so

	if (pbKey == NULL) {
		pbKey = COSE_CALLOC(cbitKey / 8, 1, context);
		CHECK_CONDITION(pbKey != NULL, COSE_ERR_OUT_OF_MEMORY);
		pcose->pbKey = pbKey;
		pcose->cbKey = cbitKey / 8;
	}

	//  If there is a recipient - ask it for the key

	for (pRecip = pcose->m_recipientFirst; pRecip != NULL; pRecip = pRecip->m_recipientNext) {
		if (_COSE_Recipient_decrypt(pRecip, cbitKey, pbKey, perr)) break;
	}
	CHECK_CONDITION(pRecip != NULL, COSE_ERR_NO_RECIPIENT_FOUND);

	//  Build protected headers

	cn_cbor * cnProtected = _COSE_arrayget_int(&pcose->m_message, INDEX_PROTECTED);
	CHECK_CONDITION((cnProtected != NULL) && (cnProtected->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

	cn_cbor * cnContent = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION((cnContent != NULL) && (cnContent->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

	//  Build authenticated data
	pbAuthData = NULL;
	pAuthData = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(pAuthData != NULL, cbor_error);

	ptmp = cn_cbor_string_create("MAC", CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);

	ptmp = cn_cbor_data_create(cnProtected->v.bytes, (int) cnProtected->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);

	ptmp = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);

	ptmp = cn_cbor_data_create(cnContent->v.bytes, (int) cnContent->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);

	cbAuthData = cn_cbor_encoder_write(RgbDontUseMac, 0, sizeof(RgbDontUseMac), pAuthData);
	pbAuthData = (byte *)COSE_CALLOC(cbAuthData, 1, context);
	CHECK_CONDITION(pbAuthData != NULL, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION((cn_cbor_encoder_write(pbAuthData, 0, cbAuthData+1, pAuthData) == cbAuthData), COSE_ERR_CBOR); // M00HACK

	switch (alg) {
	case COSE_Algorithm_HMAC_256_256:
		if (!HMAC_Validate(pcose, 256, 256, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	case COSE_Int_Alg_AES_CMAC_256_64:
		if (!AES_CMAC_Validate(pcose, 256, 64, pbAuthData, cbAuthData, perr)) goto errorReturn;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
	if ((pbKey != NULL) && (pbKeyIn == NULL)) {
		memset(pbKey, 0xff, cbitKey / 8);
		COSE_FREE(pbKey, context);
	}

	return true;

errorReturn:
	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
	if ((pbKey != NULL) && (pbKeyIn == NULL)) {
		memset(pbKey, 0xff, cbitKey / 8);
		COSE_FREE(pbKey, context);
	}

	return false;
}



HCOSE_RECIPIENT COSE_Mac_GetRecipient(HCOSE_MAC cose, int iRecipient, cose_errback * perr)
{
	int i;
	COSE_RecipientInfo * p;

	CHECK_CONDITION(IsValidMacHandle(cose), COSE_ERR_INVALID_PARAMETER);

	p = ((COSE_MacMessage *)cose)->m_recipientFirst;
	for (i = 0; i < iRecipient; i++) {
		CHECK_CONDITION(p != NULL, COSE_ERR_NO_RECIPIENT_FOUND);
		p = p->m_recipientNext;
	}
	return (HCOSE_RECIPIENT)p;

errorReturn:
	return NULL;
}
