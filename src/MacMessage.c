#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <assert.h>

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


HCOSE_MAC COSE_Mac_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_MacMessage * pobj = (COSE_MacMessage *)COSE_CALLOC(1, sizeof(COSE_MacMessage), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, CBOR_CONTEXT_PARAM_COMMA perror)) {
	error_setup:
		COSE_Mac_Free((HCOSE_MAC)pobj);
		return NULL;
	}

	if (!cn_cbor_mapput_int(pobj->m_message.m_cbor, COSE_Header_Type, cn_cbor_int_create(2, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		goto error_setup;
	}

	return (HCOSE_MAC)pobj;
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

	pRecipients = (cn_cbor *)cn_cbor_mapget_int(cbor, COSE_Header_Recipients);
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
	// if (p->pbContent != NULL) COSE_FREE(p->pbContent, &p->m_message.m_allocContext);
	//	if (p->pbIV != NULL) COSE_FREE(p->pbIV, &p->m_message.m_allocContext);
	if (p->pbKey != NULL) COSE_FREE(p->pbKey, &p->m_message.m_allocContext);

	_COSE_Release(&p->m_message);
}



HCOSE_RECIPIENT COSE_Mac_add_shared_secret(HCOSE_MAC hcose, COSE_Algorithms alg, byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, cose_errback * perror)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif // USE_CBOR_CONTEXT
	COSE_RecipientInfo * pobj;
	COSE_MacMessage * pcose = (COSE_MacMessage *)hcose;

	if (!IsValidMacHandle(hcose) || (rgbKey == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	switch (alg) {
	case COSE_Algorithm_Direct:
		break;

	default:
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}


#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	pobj = (COSE_RecipientInfo *)COSE_CALLOC(1, sizeof(COSE_RecipientInfo), context);
	if (pobj == NULL) {
	oom_error:
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
	error:
		// M00BUG COSE_Recipient_Free(pobj);
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_encrypt.m_message, CBOR_CONTEXT_PARAM_COMMA perror)) {
		goto error;
	}

	if (!cn_cbor_mapput_int(pobj->m_encrypt.m_message.m_unprotectMap, COSE_Header_Algorithm, cn_cbor_int_create(alg, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) goto error;

	if (cbKid > 0) {
		byte * pb = (byte *)COSE_CALLOC(cbKid, 1, context);
		if (pb == NULL) goto oom_error;
		memcpy(pb, rgbKid, cbKid);
		if (!cn_cbor_mapput_int(pobj->m_encrypt.m_message.m_unprotectMap, COSE_Header_KID, cn_cbor_data_create(pb, cbKid, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
			COSE_FREE(pb, context);
			goto oom_error; // M00BUG - get error from CBOR
		}
	}


	pobj->m_encrypt.pbKey = (byte *)COSE_CALLOC(cbKey, 1, context);
	if (pobj->m_encrypt.pbKey == NULL) goto error;
	memcpy(pobj->m_encrypt.pbKey, rgbKey, cbKey);
	pobj->m_encrypt.cbKey = cbKey;

	pobj->m_recipientNext = pcose->m_recipientFirst;
	pcose->m_recipientFirst = pobj;

	cn_cbor * pRecipients = (cn_cbor *)cn_cbor_mapget_int(pcose->m_message.m_cbor, COSE_Header_Recipients);
	if (pRecipients == NULL) {
		pRecipients = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
		if (pRecipients == NULL) goto error;
		if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Recipients, pRecipients, CBOR_CONTEXT_PARAM_COMMA NULL)) {
			cn_cbor_free(pRecipients, context);
			goto error;
		}
	}

	cn_cbor_array_append(pRecipients, pobj->m_encrypt.m_message.m_cbor, NULL);

	pobj->m_encrypt.m_message.m_flags |= 1;
	return (HCOSE_RECIPIENT)pobj;
}

void COSE_Mac_SetContent(HCOSE_MAC cose, const byte * rgbContent, size_t cbContent, cose_errback * errp)
{
	COSE_MacMessage * p = (COSE_MacMessage *)cose;
	cn_cbor_context * context = &p->m_message.m_allocContext;

	if (!IsValidMacHandle(cose)) {
		if (errp != NULL) errp->err = COSE_ERR_INVALID_PARAMETER;
		return;
	}

	p->pbContent = rgbContent;
	p->cbContent = cbContent;

	if (!cn_cbor_mapput_int(p->m_message.m_cbor, COSE_Header_PlainText, cn_cbor_data_create (rgbContent, cbContent, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		if (errp != NULL) errp->err = COSE_ERR_CBOR;
		return;
	}
}


const cn_cbor * COSE_Mac_map_get_int(HCOSE_MAC h, int key, int flags, cose_errback * perror)
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


bool COSE_Mac_encrypt(HCOSE_MAC h, cose_errback * perror)
{
	int alg;
	int t;
	COSE_RecipientInfo * pri;
	const cn_cbor * cn_Alg = NULL;
	byte * pbAuthData = NULL;
	cn_cbor * pAuthData = NULL;
	cn_cbor * ptmp = NULL;
	byte * pbProtected = NULL;
	ssize_t cbProtected = 0;
	size_t cbitKey;
	cn_cbor_context * context;
	COSE_Encrypt * pcose = (COSE_Encrypt *)h;
	cose_errback error;

	if (!IsValidMacHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}
#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	cn_Alg = _COSE_map_get_int(&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, &error);

	if (cn_Alg == NULL) {
	error:
		if (pbProtected != NULL) COSE_FREE(pbProtected, context);
		if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
		if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
		if (ptmp != NULL) cn_cbor_free(ptmp CBOR_CONTEXT_PARAM);
		if (perror != NULL) *perror = error;
		return false;
	}
	if (cn_Alg->type != CN_CBOR_UINT) goto error;
	alg = cn_Alg->v.uint;

	//  Get the key size

	switch (alg) {
	case COSE_Algorithm_HMAC_256_256:
		cbitKey = 256;
		break;

	default:
		goto error;
	}

	//  If we are doing direct encryption - then recipient generates the key

	if (pcose->pbKey == NULL) {
		t = 0;
		for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
			if (pri->m_encrypt.m_message.m_flags & 1) {
				t |= 1;
				pcose->pbKey = _COSE_RecipientInfo_generateKey(pri, cbitKey);
				if (pcose->pbKey == NULL) goto error;
				pcose->cbKey = cbitKey / 8;
			}
			else {
				t |= 2;
			}
		}
		if (t == 3) {
			error.err = CN_CBOR_ERR_INVALID_PARAMETER;
			goto error;
		}
	}

	if (pcose->pbKey == NULL) {
		pcose->pbKey = (byte *)COSE_CALLOC(cbitKey / 8, 1, context);
		if (pcose->pbKey == NULL) goto error;
		pcose->cbKey = cbitKey / 8;
		rand_bytes(pcose->pbKey, pcose->cbKey);
	}

	//  Build protected headers

	if (pcose->m_message.m_protectedMap->first_child != NULL) {
		cbProtected = cn_cbor_encoder_write(RgbDontUse2, 0, sizeof(RgbDontUse2), pcose->m_message.m_protectedMap);
		pbProtected = (byte *)COSE_CALLOC(cbProtected, 1, context);
		if (pbProtected == NULL) goto error;
		if (cn_cbor_encoder_write(pbProtected, 0, cbProtected, pcose->m_message.m_protectedMap) != cbProtected) goto error;
		if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Protected, cn_cbor_data_create(pbProtected, cbProtected, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) goto error;
	}
	else {
		pbProtected = NULL;
		cbProtected = 0;
	}

	//  Add Unprotected headers
	if (pcose->m_message.m_unprotectMap->first_child != NULL) {
		if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Unprotected, pcose->m_message.m_unprotectMap, CBOR_CONTEXT_PARAM_COMMA NULL)) goto error;
		pcose->m_message.m_ownUnprotectedMap = false;
	}

	//  Build authenticated data
	//  Protected headers
	//  external data
	//  body

	ssize_t cbAuthData = 0;
	pbAuthData = NULL;
	pAuthData = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);

	ptmp = cn_cbor_data_create(pbProtected, cbProtected, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (ptmp == NULL) goto error;
	cn_cbor_array_append(pAuthData, ptmp, NULL);
	pbProtected = NULL;
	ptmp = NULL;

	ptmp = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (ptmp == NULL) goto error;
	cn_cbor_array_append(pAuthData, ptmp, NULL);
	ptmp = NULL;

	ptmp = cn_cbor_data_create(pcose->pbContent, pcose->cbContent, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (ptmp == NULL) goto error;
	cn_cbor_array_append(pAuthData, ptmp, NULL);
	ptmp = NULL;

	cbAuthData = cn_cbor_encoder_write(RgbDontUse2, 0, sizeof(RgbDontUse2), pAuthData);
	pbAuthData = (byte *)COSE_CALLOC(cbAuthData, 1, context);
	if (pbAuthData == NULL) goto error;
	if (cn_cbor_encoder_write(pbAuthData, 0, cbAuthData, pAuthData) != cbAuthData) goto error;

	switch (alg) {
	case COSE_Algorithm_HMAC_256_256:
		if (!HMAC_Create(pcose, 256, 256, pbAuthData, cbAuthData, perror)) goto error;
		break;

	default:
		return false;
	}

	for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
		_COSE_Encrypt_SetContent(&pri->m_encrypt, pcose->pbKey, pcose->cbKey, &error);
		if (error.err != COSE_ERR_NONE) goto error;

		if (!COSE_Encrypt_encrypt((HCOSE_ENCRYPT)&pri->m_encrypt, &error)) goto error;
	}

	//  Figure out the clean up

	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);

	return true;
}

