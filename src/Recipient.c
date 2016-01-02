#include <stdlib.h>
#include <memory.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

bool IsValidRecipientHandle(HCOSE_RECIPIENT h)
{
	if (h == NULL) return false;
	return true;
}

HCOSE_RECIPIENT COSE_Recipient_Init(CBOR_CONTEXT_COMMA cose_errback * perror)
{
	COSE_RecipientInfo * pobj = (COSE_RecipientInfo *)COSE_CALLOC(1, sizeof(COSE_RecipientInfo), context);
	if (pobj == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(&pobj->m_encrypt.m_message, COSE_recipient_object, CBOR_CONTEXT_PARAM_COMMA perror)) {
		COSE_Recipient_Free((HCOSE_RECIPIENT)pobj);
		return NULL;
	}

	return (HCOSE_RECIPIENT)pobj;
}

bool COSE_Recipient_Free(HCOSE_RECIPIENT hRecipient)
{
	if (IsValidRecipientHandle(hRecipient)) {

		_COSE_Recipient_Free((COSE_RecipientInfo *)hRecipient);
		return true;
	}

	return false;
}


HCOSE_RECIPIENT COSE_Encrypt_GetRecipient(HCOSE_ENCRYPT cose, int iRecipient, cose_errback * perr)
{
	int i;
	COSE_RecipientInfo * p;

	if (!IsValidEncryptHandle(cose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	p = ((COSE_Encrypt *)cose)->m_recipientFirst;
	for (i = 0; i < iRecipient; i++) {
		if (p == NULL) {
			if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
			return NULL;
		}
		p = p->m_recipientNext;
	}
	return (HCOSE_RECIPIENT)p;
}

COSE_RecipientInfo * _COSE_Recipient_Init_From_Object(cn_cbor * cbor, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_RecipientInfo * pRecipient = NULL;

	pRecipient = (COSE_RecipientInfo *)COSE_CALLOC(1, sizeof(COSE_RecipientInfo), context);
	CHECK_CONDITION(pRecipient != NULL, COSE_ERR_OUT_OF_MEMORY);

#ifdef USE_ARRAY
	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
#else
	if (cbor->type != CN_CBOR_MAP) {
		if (errp != NULL) errp->err = COSE_ERR_INVALID_PARAMETER;
		COSE_FREE(pRecipient, context);
		return NULL;
	}
#endif

	if (_COSE_Encrypt_Init_From_Object(cbor, &pRecipient->m_encrypt, CBOR_CONTEXT_PARAM_COMMA perr) == NULL) {
		goto errorReturn;
	}

	return pRecipient;

errorReturn:
	_COSE_Recipient_Free(pRecipient);
	return NULL;
}

void _COSE_Recipient_Free(COSE_RecipientInfo * pRecipient)
{
	COSE_FREE(pRecipient, &pRecipient->m_encrypt.m_message.m_allocContext);

	return;
}

bool _COSE_Recipient_decrypt(COSE_RecipientInfo * pRecip, int cbitKey, byte * pbKeyIn, cose_errback * perr)
{
	int alg;
	const cn_cbor * cn = NULL;

	byte * pbKey = pbKeyIn;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif
	byte * pbAuthData = NULL;
	ssize_t cbAuthData;
	cn_cbor * pAuthData = NULL;
	byte * pbProtected = NULL;
	ssize_t cbProtected;
	cn_cbor * ptmp = NULL;
	COSE_Encrypt * pcose = &pRecip->m_encrypt;

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pRecip->m_encrypt.m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) {
	error:
	errorReturn:
		if (pbProtected != NULL) COSE_FREE(pbProtected, context);
		if (pbAuthData != NULL) COSE_FREE(pbAuthData, context);
		if (pAuthData != NULL) cn_cbor_free(pAuthData CBOR_CONTEXT_PARAM);
		if ((pbKey != NULL) && (pbKeyIn == NULL)) {
			memset(pbKey, 0xff, cbitKey / 8);
			COSE_FREE(pbKey, context);
		}
		return false;
	}
	CHECK_CONDITION((cn->type == CN_CBOR_UINT) || (cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn->v.uint;

	CHECK_CONDITION(pbKey != NULL, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
	case COSE_Algorithm_Direct:
		CHECK_CONDITION((pcose->pbKey != NULL) || (pRecip->m_pkey != NULL), COSE_ERR_INVALID_PARAMETER);
		if (pRecip->m_pkey != NULL) {
			cn = cn_cbor_mapget_int(pRecip->m_pkey, -1);
			CHECK_CONDITION((cn != NULL) && (cn->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);
			CHECK_CONDITION((cn->length == (unsigned int)cbitKey / 8), COSE_ERR_INVALID_PARAMETER);
			memcpy(pbKey, cn->v.bytes, cn->length);

			return true;
		}
		CHECK_CONDITION(pcose->cbKey == (unsigned int)cbitKey / 8, COSE_ERR_INVALID_PARAMETER);
		memcpy(pbKey, pcose->pbKey, pcose->cbKey);
		return true;

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
		if (_COSE_Recipient_decrypt(pRecip, cbitKey, pbKey, perr)) break;
	}

	switch (alg) {
	case COSE_Algorithm_Direct:
		CHECK_CONDITION((pcose->cbKey == (unsigned int)cbitKey / 8), COSE_ERR_INVALID_PARAMETER);
		memcpy(pbKey, pcose->pbKey, pcose->cbKey);
		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	if (perr != NULL) perr->err = COSE_ERR_NONE;

	return true;
}

byte * _COSE_RecipientInfo_generateKey(COSE_RecipientInfo * pRecipient, size_t cbitKeySize, cose_errback * perr)
{
	int alg;
	const cn_cbor * cn_Alg = _COSE_map_get_int(&pRecipient->m_encrypt.m_message, COSE_Header_Algorithm, COSE_BOTH, perr);

	CHECK_CONDITION(cn_Alg != NULL, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION((cn_Alg->type == CN_CBOR_UINT) || (cn_Alg->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn_Alg->v.uint;

	switch (alg) {
	case COSE_Algorithm_Direct:
	{
		byte * pb;
		if (pRecipient->m_pkey != NULL) {
			const cn_cbor * pK = cn_cbor_mapget_int(pRecipient->m_pkey, -1);
			CHECK_CONDITION((pK != NULL) && (pK->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);
			CHECK_CONDITION(pK->length == cbitKeySize / 8, COSE_ERR_INVALID_PARAMETER);
			pb = COSE_CALLOC(cbitKeySize / 8, 1, &pRecipient->m_encrypt.m_message.m_allocContext);
			CHECK_CONDITION(pb != NULL, COSE_ERR_OUT_OF_MEMORY);
			memcpy(pb, pK->v.bytes, cbitKeySize / 8);
		}
		else {
			if (pRecipient->m_encrypt.cbKey != cbitKeySize / 8) return NULL;
			pb = (byte *)malloc(cbitKeySize / 8);
			if (pb == NULL) return NULL;
			memcpy(pb, pRecipient->m_encrypt.pbKey, cbitKeySize / 8);
		}
		return pb;
	}
	break;

	case COSE_Algorithm_ECDH_SS_HKDF_256: {
		//  Need to have a key and it needs to be the correct type of key.
		if ((pRecipient->m_pkey == NULL) || (cn_cbor_mapget_int(pRecipient->m_pkey, 1)->v.uint != 2)) return NULL;
		break;
	}

	default:
		return NULL;
	}

errorReturn:
	return NULL;
}

bool COSE_Recipient_SetKey_secret(HCOSE_RECIPIENT h, const byte * pbKey, int cbKey, cose_errback * perror)
{
	COSE_RecipientInfo * p;

	if (!IsValidRecipientHandle(h) || (pbKey == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_CBOR;
		return false;
	}

	p = (COSE_RecipientInfo *)h;

	p->m_encrypt.pbKey = (byte *)COSE_CALLOC(cbKey, 1, &p->m_encrypt.m_message.m_allocContext);
	if (p->m_encrypt.pbKey == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return false;
	}

	memcpy(p->m_encrypt.pbKey, pbKey, cbKey);
	p->m_encrypt.cbKey = cbKey;

	return true;
}

bool COSE_Recipient_SetKey(HCOSE_RECIPIENT h, const cn_cbor * pKey, cose_errback * perror)
{
	COSE_RecipientInfo * p;

	if (!IsValidRecipientHandle(h) || (pKey == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}



	p = (COSE_RecipientInfo *)h;
	p->m_pkey = pKey;

	return true;
}

bool COSE_Recipient_map_put(HCOSE_RECIPIENT h, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	if (!IsValidRecipientHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	if (!_COSE_map_put(&((COSE_RecipientInfo *)h)->m_encrypt.m_message, key, value, flags, perror)) return false;

	if (key == COSE_Header_Algorithm) {
		if (value->type == CN_CBOR_INT) {
			switch (value->v.uint) {
			case COSE_Algorithm_Direct:
			case COSE_Algorithm_ECDH_ES_HKDF_256:
			case COSE_Algorithm_ECDH_ES_HKDF_512:
				((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags |= 1;
				break;

			default:
				((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags &= ~1;
				break;
			}
		}
		else {
			((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags &= ~1;
		}
	}

	return true;
}

