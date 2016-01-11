#include <stdlib.h>
#include <memory.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

COSE* RecipientRoot = NULL;

bool IsValidRecipientHandle(HCOSE_RECIPIENT h)
{
	COSE_RecipientInfo * p = (COSE_RecipientInfo *)h;

	if (p == NULL) return false;
	return _COSE_IsInList(RecipientRoot, &p->m_encrypt.m_message);
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

	_COSE_InsertInList(&RecipientRoot, &pobj->m_encrypt.m_message);
	return (HCOSE_RECIPIENT)pobj;
}

bool COSE_Recipient_Free(HCOSE_RECIPIENT hRecipient)
{
	if (IsValidRecipientHandle(hRecipient)) {
		COSE_RecipientInfo * p = (COSE_RecipientInfo *)hRecipient;
		_COSE_RemoveFromList(&RecipientRoot, &p->m_encrypt.m_message);

		_COSE_Recipient_Free(p);
		return true;
	}


	return false;
}


HCOSE_RECIPIENT COSE_Enveloped_GetRecipient(HCOSE_ENVELOPED cose, int iRecipient, cose_errback * perr)
{
	int i;
	COSE_RecipientInfo * p;

	if (!IsValidEnvelopedHandle(cose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	p = ((COSE_Enveloped *)cose)->m_recipientFirst;
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

	if (_COSE_Enveloped_Init_From_Object(cbor, &pRecipient->m_encrypt, CBOR_CONTEXT_PARAM_COMMA perr) == NULL) {
		goto errorReturn;
	}

	_COSE_InsertInList(&RecipientRoot, &pRecipient->m_encrypt.m_message);

	return pRecipient;

errorReturn:
	_COSE_Recipient_Free(pRecipient);
	return NULL;
}

void _COSE_Recipient_Free(COSE_RecipientInfo * pRecipient)
{
	if (pRecipient->m_encrypt.m_message.m_refCount > 1) {
		pRecipient->m_encrypt.m_message.m_refCount--;
		return;
	}

	COSE_FREE(pRecipient, &pRecipient->m_encrypt.m_message.m_allocContext);

	return;
}

bool _COSE_Recipient_decrypt(COSE_RecipientInfo * pRecip, int cbitKey, byte * pbKeyIn, cose_errback * perr)
{
	int alg;
	const cn_cbor * cn = NULL;
	COSE_RecipientInfo * pRecip2;
	byte * pbKey = pbKeyIn;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context;
#endif
	byte * pbAuthData = NULL;
	cn_cbor * pAuthData = NULL;
	byte * pbProtected = NULL;
	COSE_Enveloped * pcose = &pRecip->m_encrypt;
	cn_cbor * cnBody = NULL;

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pRecip->m_encrypt.m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) {
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

	case COSE_Algorithm_AES_KW_128:
	case COSE_Algorithm_AES_KW_192:
	case COSE_Algorithm_AES_KW_256:
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

	for (pRecip2 = pcose->m_recipientFirst; pRecip2 != NULL; pRecip2 = pRecip->m_recipientNext) {
		if (_COSE_Recipient_decrypt(pRecip2, cbitKey, pbKey, perr)) break;
	}

	cnBody = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION(cnBody != NULL, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
	case COSE_Algorithm_AES_KW_128:
	case COSE_Algorithm_AES_KW_256:
		CHECK_CONDITION((pcose->pbKey != NULL) || (pRecip->m_pkey != NULL), COSE_ERR_INVALID_PARAMETER);
		if (pRecip->m_pkey != NULL) {
			int x = cbitKey / 8;
			cn = cn_cbor_mapget_int(pRecip->m_pkey, -1);
			CHECK_CONDITION((cn != NULL) && (cn->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, cn->v.bytes, cn->length * 8, cnBody->v.bytes, cnBody->length, pbKey, &x, perr)) goto errorReturn;
		}
		else {
			CHECK_CONDITION(pcose->cbKey == (unsigned int)cbitKey / 8, COSE_ERR_INVALID_PARAMETER);
			memcpy(pbKey, pcose->pbKey, pcose->cbKey);
		}

		break;

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	return true;
}

bool _COSE_Recipient_encrypt(COSE_RecipientInfo * pRecipient, const byte * pbContent, size_t cbContent, cose_errback * perr)
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
	cn_cbor_errback cbor_error;

#ifdef USE_CBOR_CONTEXT
	context = &pRecipient->m_encrypt.m_message.m_allocContext;
#endif // USE_CBOR_CONTEXT

	cn_Alg = _COSE_map_get_int(&pRecipient->m_encrypt.m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn_Alg == NULL) goto errorReturn;

	CHECK_CONDITION((cn_Alg->type == CN_CBOR_UINT) || (cn_Alg->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn_Alg->v.uint;

	//  Get the key size

	switch (alg) {
	case COSE_Algorithm_Direct:
		//  This is a NOOP
		cbitKey = 0;
		CHECK_CONDITION(pRecipient->m_encrypt.m_recipientFirst == NULL, COSE_ERR_INVALID_PARAMETER);
		break;

	case COSE_Algorithm_AES_KW_128:
		cbitKey = 128;
		break;

	case COSE_Algorithm_AES_KW_192:
		cbitKey = 192;
		break;

	case COSE_Algorithm_AES_KW_256:
		cbitKey = 256;
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	//  If we are doing direct encryption - then recipient generates the key

	if ((pRecipient->m_encrypt.m_recipientFirst != NULL) && ( pRecipient->m_encrypt.pbKey == NULL)) {
		t = 0;
		for (pri = pRecipient->m_encrypt.m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
			if (pri->m_encrypt.m_message.m_flags & 1) {
				t |= 1;
				pRecipient->m_encrypt.pbKey = _COSE_RecipientInfo_generateKey(pri, cbitKey, perr);
				if (pRecipient->m_encrypt.pbKey == NULL) goto errorReturn;
				pRecipient->m_encrypt.cbKey = cbitKey / 8;
			}
			else {
				t |= 2;
			}
		}
		CHECK_CONDITION(t != 3, COSE_ERR_INVALID_PARAMETER);
	}

	//   Do we need to generate a random key at this point - 
	//   This is only true if we both haven't done it and and we have a recipient to encrypt it.

	if ((pRecipient->m_pkey!= NULL) && (pRecipient->m_encrypt.pbKey == NULL)) {
		pRecipient->m_encrypt.pbKey = (byte *)COSE_CALLOC(cbitKey / 8, 1, context);
		CHECK_CONDITION(pRecipient->m_encrypt.pbKey != NULL, COSE_ERR_OUT_OF_MEMORY);
		pRecipient->m_encrypt.cbKey = cbitKey / 8;
		rand_bytes(pRecipient->m_encrypt.pbKey, pRecipient->m_encrypt.cbKey);
	}

	//  Build protected headers

	const cn_cbor * cbProtected = _COSE_encode_protected(&pRecipient->m_encrypt.m_message, perr);
	if (cbProtected == NULL) goto errorReturn;

	//  Build authenticated data
	size_t cbAuthData = 0;
	if (!_COSE_Encrypt_Build_AAD(&pRecipient->m_encrypt.m_message, &pbAuthData, &cbAuthData, "Recipient", perr)) goto errorReturn;

	switch (alg) {

	case COSE_Algorithm_Direct:
		ptmp = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(ptmp != NULL, cbor_error);
		CHECK_CONDITION_CBOR(_COSE_array_replace(&pRecipient->m_encrypt.m_message, ptmp, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA &cbor_error), cbor_error);
		break;

	case COSE_Algorithm_AES_KW_256:
		if (pRecipient->m_pkey != NULL) {
			cn_cbor * pK = cn_cbor_mapget_int(pRecipient->m_pkey, -1);
			CHECK_CONDITION(pK != NULL, COSE_ERR_INVALID_PARAMETER);
			if (!AES_KW_Encrypt(pRecipient, pK->v.bytes, (int) pK->length*8, pbContent, (int) cbContent, perr)) goto errorReturn;
		}
		else {
			if (!AES_KW_Encrypt(pRecipient, NULL, 0, pbContent, (int) cbContent, perr)) goto errorReturn;
		}
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	for (pri = pRecipient->m_encrypt.m_recipientFirst; pri != NULL; pri = pri->m_recipientNext) {
		if (!_COSE_Recipient_encrypt(pri, pRecipient->m_encrypt.pbKey, pRecipient->m_encrypt.cbKey, perr)) goto errorReturn;
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

