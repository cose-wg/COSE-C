#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

byte RgbDontUse[8 * 1024];   //  Remove this array when we can compute the size of a cbor serialization without this hack.


bool IsValidEncryptHandle(HCOSE_ENCRYPT h)
{
	COSE_Encrypt * p = (COSE_Encrypt *)h;
	if (p == NULL) return false;
	return true;
}


size_t COSE_Encode(HCOSE msg, byte * rgb, int ib, size_t cb)
{
	if (rgb == NULL) return cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), ((COSE *)msg)->m_cbor) + ib;
	return cbor_encoder_write(rgb, ib, cb, ((COSE*)msg)->m_cbor);
}

HCOSE_ENCRYPT COSE_Encrypt_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_Encrypt * pobj = (COSE_Encrypt *)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_message, CBOR_CONTEXT_PARAM_COMMA perror)) {
	error_setup:
		COSE_Encrypt_Free((HCOSE_ENCRYPT)pobj);
		return NULL;
	}

	if (!cn_cbor_mapput_int(pobj->m_message.m_cbor, COSE_Header_Type, cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		goto error_setup;
	}

	return (HCOSE_ENCRYPT) pobj;
}

HCOSE_ENCRYPT _COSE_Encrypt_Init_From_Object(cn_cbor * cbor, COSE_Encrypt * pIn, CBOR_CONTEXT_COMMA cose_errback * errp)
{
	COSE_Encrypt * pobj = pIn;
	cn_cbor * pRecipients = NULL;

	if (pobj == NULL) pobj = (COSE_Encrypt *)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	if (pobj == NULL) {
		if (errp != NULL) errp->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA errp)) {
		return NULL;
	}

	pRecipients = (cn_cbor *) cn_cbor_mapget_int(cbor, COSE_Header_Recipients);
	while (pRecipients != NULL) {
		COSE_RecipientInfo * pInfo = _COSE_Recipient_Init_From_Object(pRecipients, CBOR_CONTEXT_PARAM_COMMA errp);
		if (pInfo == NULL) {
			if (pIn == NULL) COSE_Encrypt_Free((HCOSE_ENCRYPT) pobj);
			return NULL;
		}

		pInfo->m_recipientNext = pobj->m_recipientFirst;
		pobj->m_recipientFirst = pInfo;
		pRecipients = pRecipients->next;
	}

	return(HCOSE_ENCRYPT) pobj;
}

bool COSE_Encrypt_Free(HCOSE_ENCRYPT h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif

	if (!IsValidEncryptHandle(h)) return false;

#ifdef USE_CBOR_CONTEXT
	context = ((COSE_Encrypt *)h)->m_message.m_allocContext;
#endif

	_COSE_Encrypt_Release((COSE_Encrypt *)h);

	COSE_FREE((COSE_Encrypt *)h, &context);

	return true;
}

void _COSE_Encrypt_Release(COSE_Encrypt * p)
{
	if (p->pbContent != NULL) COSE_FREE(p->pbContent, &p->m_message.m_allocContext);
	//	if (p->pbIV != NULL) COSE_FREE(p->pbIV, &p->m_message.m_allocContext);
	if (p->pbKey != NULL) COSE_FREE(p ->pbKey, &p->m_message.m_allocContext);

	_COSE_Release(&p->m_message);
}

HCOSE_RECIPIENT COSE_Encrypt_add_shared_secret(HCOSE_ENCRYPT hcose, COSE_Algorithms alg, byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, cose_errback * perror)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif // USE_CBOR_CONTEXT
	COSE_RecipientInfo * pobj;
	COSE_Encrypt * pcose = (COSE_Encrypt *)hcose;

	if (!IsValidEncryptHandle(hcose) || (rgbKey == NULL)) {
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

	pobj = (COSE_RecipientInfo *) COSE_CALLOC(1, sizeof(COSE_RecipientInfo) , context);
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


	pobj->m_encrypt.pbKey = (byte *) COSE_CALLOC(cbKey, 1, context);
	if (pobj->m_encrypt.pbKey == NULL) goto error;
	memcpy(pobj->m_encrypt.pbKey, rgbKey, cbKey);
	pobj->m_encrypt.cbKey = cbKey;

	pobj->m_recipientNext = pcose->m_recipientFirst;
	pcose->m_recipientFirst = pobj;

	cn_cbor * pRecipients = (cn_cbor *) cn_cbor_mapget_int(pcose->m_message.m_cbor, COSE_Header_Recipients);
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
	return (HCOSE_RECIPIENT) pobj;
}

bool COSE_Encrypt_decrypt(HCOSE_ENCRYPT h, HCOSE_RECIPIENT hRecip, cose_errback * perr)
{
	COSE_Encrypt * pcose = (COSE_Encrypt *)h;
	COSE_RecipientInfo * pRecip = (COSE_RecipientInfo *)hRecip;

	if (!IsValidEncryptHandle(h) || (!IsValidRecipientHandle(hRecip))) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_Encrypt_decrypt(pcose, pRecip, perr);
}

bool _COSE_Encrypt_decrypt(COSE_Encrypt * pcose, COSE_RecipientInfo * pRecip, cose_errback * perr)
{
	int alg;
	int cbitKey;
	const cn_cbor * cn = NULL;
	cose_errback error = { 0 };

	byte * pbKey = NULL;
	cn_cbor_context * context;
	byte * pbAuthData = NULL;
	ssize_t cbAuthData;
	cn_cbor * pAuthData = NULL;
	byte * pbProtected = NULL;
	ssize_t cbProtected;
	cn_cbor * ptmp = NULL;

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, &error);

	if (cn == NULL) {
	error:
		if (pbProtected != NULL) COSE_FREE(pbProtected, context);
		if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
		if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
		if (pbKey != NULL) COSE_FREE(pbKey, context);
		if (perr != NULL) *perr = error;
		return false;
	}
	if (cn->type != CN_CBOR_UINT) goto error;
	alg = cn->v.uint;

	switch (alg) {
	case COSE_Algorithm_AES_CCM_64:
		cbitKey = 128;
		break;

	default:
		error.err = COSE_ERR_UNKNOWN_ALGORITHM;
		goto error;
	}

	pbKey = COSE_CALLOC(cbitKey / 8, 1, context);

	for (pRecip = pcose->m_recipientFirst; pRecip != NULL; pRecip = pRecip->m_recipientNext) {
		if (_COSE_Recipient_decrypt(pRecip, cbitKey, pbKey, &error)) break;
	}

	if (pRecip == NULL) {
		error.err = COSE_ERR_NO_RECIPIENT_FOUND;
		goto error;
	}

	//  Build protected headers

	if (pcose->m_message.m_protectedMap->first_child != NULL) {
		cbProtected = cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), pcose->m_message.m_protectedMap);
		pbProtected = (byte *)COSE_CALLOC(cbProtected, 1, context);
		if (pbProtected == NULL) goto error;
		if (cbor_encoder_write(pbProtected, 0, cbProtected, pcose->m_message.m_protectedMap) != cbProtected) goto error;
		if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Protected, cn_cbor_data_create(pbProtected, cbProtected, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) goto error;
	}
	else {
		pbProtected = NULL;
		cbProtected = 0;
	}

	//  Build authenticated data
	pbAuthData = NULL;
	pAuthData = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);

	ptmp = cn_cbor_data_create(pbProtected, cbProtected, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (ptmp == NULL) goto error;
	cn_cbor_array_append(pAuthData, ptmp, NULL);
	pbProtected = NULL;

	ptmp = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (ptmp == NULL) goto error;
	cn_cbor_array_append(pAuthData, ptmp, NULL);

	cbAuthData = cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), pAuthData);
	pbAuthData = (byte *)COSE_CALLOC(cbAuthData, 1, context);
	if (pbAuthData == NULL) goto error;
	if (cbor_encoder_write(pbAuthData, 0, cbAuthData, pAuthData) != cbAuthData) goto error;

	switch (alg) {
	case COSE_Algorithm_AES_CCM_64:
		if (!AES_CCM_Decrypt(pcose, 8, 8, pbAuthData, cbAuthData)) {
			error.err = COSE_ERR_DECRYPT_FAILED;
			goto error;
		}
		break;

	default:
		error.err = COSE_ERR_UNKNOWN_ALGORITHM;
		goto error;
	}

	return true;
}

bool COSE_Encrypt_encrypt(HCOSE_ENCRYPT h, cose_errback * perror)
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
	COSE_Encrypt * pcose = (COSE_Encrypt *) h;
	cose_errback error;

	if (!IsValidEncryptHandle(h)) {
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
	case COSE_Algorithm_AES_CCM_64:
		cbitKey = 128;
		break;

	case COSE_Algorithm_Direct:
		cbitKey = 0;
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
		pcose->pbKey = (byte *) COSE_CALLOC(cbitKey/8, 1, context);
		if (pcose->pbKey == NULL) goto error;
		pcose->cbKey = cbitKey / 8;
		rand_bytes(pcose->pbKey, pcose->cbKey);
	}

	//  Build protected headers

	if (pcose->m_message.m_protectedMap->first_child != NULL) {
		cbProtected = cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), pcose->m_message.m_protectedMap);
		pbProtected = (byte *) COSE_CALLOC(cbProtected, 1, context);
		if (pbProtected == NULL) goto error;
		if (cbor_encoder_write(pbProtected, 0, cbProtected, pcose->m_message.m_protectedMap) != cbProtected) goto error;
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

	cbAuthData = cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), pAuthData);
	pbAuthData = (byte *) COSE_CALLOC(cbAuthData, 1, context);
	if (pbAuthData == NULL) goto error;
	if (cbor_encoder_write(pbAuthData, 0, cbAuthData, pAuthData) != cbAuthData) goto error;

	switch (alg) {
#ifdef INCLUDE_AES_CCM_64
	case COSE_Algorithm_AES_CCM_64:
		if (!AES_CCM_Encrypt(pcose, 64, 8, pbAuthData, cbAuthData)) goto error;
		break;
#endif

	case COSE_Algorithm_Direct:
		break;

	default:
		return false;
	}

	for (pri = pcose->m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
		_COSE_Encrypt_SetContent(&pri->m_encrypt, pcose->pbKey, pcose->cbKey, &error);
		if (error.err != COSE_ERR_NONE) goto error;

		if (!COSE_Encrypt_encrypt((HCOSE_ENCRYPT) &pri->m_encrypt, &error)) goto error;
	}

	//  Figure out the clean up

	if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
	if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);

	return true;
}

void COSE_Encrypt_SetContent(HCOSE_ENCRYPT h, const byte * rgb, size_t cb, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h) || (rgb == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
	}

	_COSE_Encrypt_SetContent((COSE_Encrypt *)h, rgb, cb, perror);
}

void _COSE_Encrypt_SetContent(COSE_Encrypt * cose, const byte * rgb, size_t cb, cose_errback * perror)
{
	cose->pbContent = (byte *)COSE_CALLOC(cb, 1, &cose->m_message.m_allocContext);
	if (cose->pbContent == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return;
	}
	memcpy(cose->pbContent, rgb, cb);
	cose->cbContent = cb;

	if (perror != NULL) perror->err = COSE_ERR_NONE;
	return;
}

const cn_cbor * COSE_Encrypt_map_get_int(HCOSE_ENCRYPT h, int key, int flags, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_Encrypt *)h)->m_message, key, flags, perror);
}


bool COSE_Encrypt_map_put(HCOSE_ENCRYPT h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_Encrypt *)h)->m_message, key, value, flags, perror);
}
