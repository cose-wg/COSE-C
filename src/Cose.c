#include <stdlib.h>
#ifndef __MBED__
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "cose_crypto.h"

bool IsValidCOSEHandle(HCOSE h)
{
	COSE_Encrypt *p = (COSE_Encrypt *)h;
	if (p == NULL) {
		return false;
	}
	return true;
}

bool _COSE_Init(COSE_INIT_FLAGS flags,
	COSE *pcose,
	int msgType,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	cn_cbor_errback errState;
	;

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) {
		pcose->m_allocContext = *context;
	}
#endif

	CHECK_CONDITION((flags & ~(COSE_INIT_FLAGS_DETACHED_CONTENT |
								 COSE_INIT_FLAGS_NO_CBOR_TAG)) == 0,
		COSE_ERR_INVALID_PARAMETER);

	pcose->m_flags = flags;

	pcose->m_protectedMap =
		cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & errState);
	CHECK_CONDITION_CBOR(pcose->m_protectedMap != NULL, errState);

	pcose->m_dontSendMap =
		cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & errState);
	CHECK_CONDITION_CBOR(pcose->m_dontSendMap != NULL, errState);

	pcose->m_cborRoot = pcose->m_cbor =
		cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & errState);
	CHECK_CONDITION_CBOR(pcose->m_cbor != NULL, errState);
	pcose->m_ownMsg = 1;

	pcose->m_msgType = msgType;

	pcose->m_unprotectMap =
		cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & errState);
	CHECK_CONDITION_CBOR(pcose->m_unprotectMap != NULL, errState);
	pcose->m_ownUnprotectedMap = true;
	CHECK_CONDITION_CBOR(
		_COSE_array_replace(pcose, pcose->m_unprotectMap, INDEX_UNPROTECTED,
			CBOR_CONTEXT_PARAM_COMMA & errState),
		errState);
	pcose->m_ownUnprotectedMap = false;

	if (!(flags & COSE_INIT_FLAGS_NO_CBOR_TAG)) {
		cn_cbor_errback cbor_error;
		cn_cbor *cn = cn_cbor_tag_create(
			msgType, pcose->m_cborRoot, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
		pcose->m_cborRoot = cn;
	}

	pcose->m_refCount = 1;

	return true;

errorReturn:
	return false;
}

bool _COSE_Init_From_Object(COSE *pobj,
	cn_cbor *pcbor,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	const cn_cbor *pmap = NULL;
	cn_cbor_errback errState;  // = { 0 };
	cn_cbor_errback cbor_error;

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) {
		pobj->m_allocContext = *context;
	}
#endif
	pobj->m_cborRoot = pcbor;
	pobj->m_cbor = pcbor;

	//  Check if we have a tag
	if (pcbor->type == CN_CBOR_TAG) {
		pobj->m_cbor = pcbor->first_child;
	}

	pmap = _COSE_arrayget_int(pobj, INDEX_PROTECTED);

	CHECK_CONDITION(pmap != NULL, COSE_ERR_INVALID_PARAMETER);
	if (pmap != NULL) {
		CHECK_CONDITION(
			pmap->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

		if (pmap->length == 0) {
			pobj->m_protectedMap =
				cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
			CHECK_CONDITION(pobj->m_protectedMap, COSE_ERR_OUT_OF_MEMORY);
		}
		else {
			pobj->m_protectedMap = cn_cbor_decode((const byte *)pmap->v.str,
				pmap->length, CBOR_CONTEXT_PARAM_COMMA & errState);
			CHECK_CONDITION(
				pobj->m_protectedMap != NULL, COSE_ERR_INVALID_PARAMETER);
		}
	}

	pobj->m_unprotectMap = _COSE_arrayget_int(pobj, INDEX_UNPROTECTED);
	CHECK_CONDITION((pobj->m_unprotectMap != NULL) &&
						(pobj->m_unprotectMap->type == CN_CBOR_MAP),
		COSE_ERR_INVALID_PARAMETER);
	pobj->m_ownUnprotectedMap = false;

	pobj->m_dontSendMap =
		cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(pobj->m_dontSendMap != NULL, cbor_error);

#if INCLUDE_COUNTERSIGNATURE
	cn_cbor *pCounter =
		cn_cbor_mapget_int(pobj->m_unprotectMap, COSE_Header_CounterSign);
	if (pCounter != NULL) {
		int i;
		CHECK_CONDITION(
			pCounter->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(pCounter->length > 0, COSE_ERR_INVALID_PARAMETER);
		if (pCounter->first_child->type == CN_CBOR_ARRAY) {
			cn_cbor *pSig = pCounter->first_child;
			for (i = 0; i < pCounter->length; i++, pSig = pSig->next) {
				COSE_CounterSign *cs = _COSE_CounterSign_Init_From_Object(
					pSig, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
				cs->m_next = pobj->m_counterSigners;
				pobj->m_counterSigners = cs;
			}
		}
		else {
			COSE_CounterSign *cs = _COSE_CounterSign_Init_From_Object(
				pCounter, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			pobj->m_counterSigners = cs;
		}
	}
#endif

	pobj->m_ownMsg = true;
	pobj->m_refCount = 1;

	return true;

errorReturn:
	return false;
}

void _COSE_Release(COSE *pcose)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_allocContext;
#endif

	if (pcose->m_protectedMap != NULL) {
		CN_CBOR_FREE(pcose->m_protectedMap, context);
	}
	if (pcose->m_ownUnprotectedMap && (pcose->m_unprotectMap != NULL)) {
		CN_CBOR_FREE(pcose->m_unprotectMap, context);
	}
	if (pcose->m_dontSendMap != NULL) {
		CN_CBOR_FREE(pcose->m_dontSendMap, context);
	}
	if (pcose->m_ownMsg && (pcose->m_cborRoot != NULL) &&
		(pcose->m_cborRoot->parent == NULL)) {
		CN_CBOR_FREE(pcose->m_cborRoot, context);
	}

#if INCLUDE_COUNTERSIGNATURE
	if (pcose->m_counterSigners != NULL) {
		COSE_CounterSign *p = pcose->m_counterSigners;
		COSE_CounterSign *p2 = NULL;

		while (p != NULL) {
			p2 = p->m_next;
			COSE_CounterSign_Free((HCOSE_COUNTERSIGN)p);
			p = p2;
		}
	}
#endif
}

HCOSE COSE_Decode(const byte *rgbData,
	size_t cbData,
	int *ptype,
	COSE_object_type struct_type,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	cn_cbor *cbor = NULL;
	cn_cbor_errback cbor_err;
	HCOSE h;

	CHECK_CONDITION(
		(rgbData != NULL) && (ptype != NULL), COSE_ERR_INVALID_PARAMETER);

	cbor = 
		cn_cbor_decode(rgbData, cbData, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
	CHECK_CONDITION_CBOR(cbor != NULL, cbor_err);

	if (cbor->type == CN_CBOR_TAG) {
		if (struct_type != 0) {
			CHECK_CONDITION(struct_type == (COSE_object_type)cbor->v.sint,
				COSE_ERR_INVALID_PARAMETER);
		}
		else {
			struct_type = cbor->v.uint;
		}
		*ptype = struct_type;

		cn_cbor *ptag = cbor;
		cbor = ptag->first_child;
		ptag->first_child = NULL;
		ptag->last_child = NULL;
		cbor->parent = NULL;
		CN_CBOR_FREE(ptag, context);
	}
	else {
		*ptype = struct_type;
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

	cn_cbor *cbor2 = cbor;
	cbor = NULL;
	switch (*ptype) {
		case COSE_enveloped_object:
#if INCLUDE_ENCRYPT
			h = (HCOSE)_COSE_Enveloped_Init_From_Object(
				cbor2, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			if (h == NULL) {
				goto errorReturn;
			}
#else
			FAIL_CONDITION(COSE_ERR_UNSUPPORTED_COSE_TYPE);
#endif
			break;

		case COSE_sign_object:
#if INCLUDE_SIGN
			h = (HCOSE)_COSE_Sign_Init_From_Object(
				cbor2, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			if (h == NULL) {
				goto errorReturn;
			}
#else
			FAIL_CONDITION(COSE_ERR_UNSUPPORTED_COSE_TYPE);
#endif
			break;

		case COSE_sign1_object:
#if INCLUDE_SIGN1
			h = (HCOSE)_COSE_Sign1_Init_From_Object(
				cbor2, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			if (h == NULL) {
				goto errorReturn;
			}
#else
			FAIL_CONDITION(COSE_ERR_UNSUPPORTED_COSE_TYPE);
#endif
			break;

		case COSE_mac_object:
#if INCLUDE_MAC
			h = (HCOSE)_COSE_Mac_Init_From_Object(
				cbor2, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			if (h == NULL) {
				goto errorReturn;
			}
#else
			FAIL_CONDITION(COSE_ERR_UNSUPPORTED_COSE_TYPE);
#endif
			break;

		case COSE_mac0_object:
#if INCLUDE_MAC0
			h = (HCOSE)_COSE_Mac0_Init_From_Object(
				cbor2, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			if (h == NULL) {
				goto errorReturn;
			}
#else
			FAIL_CONDITION(COSE_ERR_UNSUPPORTED_COSE_TYPE);
#endif
			break;

		case COSE_encrypt_object:
#if INCLUDE_ENCRYPT0
			h = (HCOSE)_COSE_Encrypt_Init_From_Object(
				cbor2, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
			if (h == NULL) {
				goto errorReturn;
			}
#else
			FAIL_CONDITION(COSE_ERR_UNSUPPORTED_COSE_TYPE);
#endif
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	return h;

errorReturn:
	// M00TODO - break up the init and allocation above for memory tests.
	CN_CBOR_FREE(cbor, context);
	return NULL;
}

size_t COSE_Encode(HCOSE msg, byte *rgb, size_t ib, size_t cb)
{
	if (rgb == NULL) {
		return cn_cbor_encode_size(((COSE *)msg)->m_cbor) + ib;
	}
	ssize_t size = cn_cbor_encoder_write(rgb, ib, cb, ((COSE *)msg)->m_cbor);
	return size >= 0 ? size : 0;
}

cn_cbor *COSE_get_cbor(HCOSE h)
{
	COSE *msg = (COSE *)h;
	if (!IsValidCOSEHandle(h)) {
		return NULL;
	}

	return msg->m_cbor;
}

bool _COSE_SetExternal(COSE *pcose,
	const byte *pbExternalData,
	size_t cbExternalData,
	cose_errback *perr)
{
	(void)perr;
	pcose->m_pbExternal = pbExternalData;
	pcose->m_cbExternal = cbExternalData;

	return true;
}

cn_cbor *_COSE_map_get_int(COSE *cose, int key, int flags, cose_errback *perr)
{
	cn_cbor *p = NULL;

	if (perr != NULL) {
		perr->err = COSE_ERR_NONE;
	}

	if ((cose->m_protectedMap != NULL) && ((flags & COSE_PROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_int(cose->m_protectedMap, key);
		if (p != NULL) {
			return p;
		}
	}

	if ((cose->m_unprotectMap != NULL) &&
		((flags & COSE_UNPROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_int(cose->m_unprotectMap, key);
		if (p != NULL) {
			return p;
		}
	}

	if ((cose->m_dontSendMap != NULL) && ((flags & COSE_DONT_SEND) != 0)) {
		p = cn_cbor_mapget_int(cose->m_dontSendMap, key);
	}

	if ((p == NULL) && (perr != NULL)) {
		perr->err = COSE_ERR_INVALID_PARAMETER;
	}

	return p;
}

cn_cbor *_COSE_map_get_str(COSE *pcose,
	const char *key,
	int flags,
	cose_errback *perror)
{
	cn_cbor *p = NULL;

	if (perror != NULL) {
		perror->err = COSE_ERR_NONE;
	}

	if ((pcose->m_protectedMap != NULL) && ((flags & COSE_PROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_string(pcose->m_protectedMap, key);
		if (p != NULL) {
			return p;
		}
	}

	if ((pcose->m_unprotectMap != NULL) &&
		((flags & COSE_UNPROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_string(pcose->m_unprotectMap, key);
	}

	if ((pcose->m_dontSendMap != NULL) && ((flags & COSE_DONT_SEND) != 0)) {
		p = cn_cbor_mapget_string(pcose->m_dontSendMap, key);
	}

	return p;
}

bool _COSE_map_put(COSE *cose,
	int key,
	cn_cbor *value,
	int flags,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &cose->m_allocContext;
#endif
	cn_cbor_errback error;
	bool f = false;
	CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

	CHECK_CONDITION(cn_cbor_mapget_int(cose->m_protectedMap, key) == NULL,
		COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(cn_cbor_mapget_int(cose->m_unprotectMap, key) == NULL,
		COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(cn_cbor_mapget_int(cose->m_dontSendMap, key) == NULL,
		COSE_ERR_INVALID_PARAMETER);

	switch (flags) {
		case COSE_PROTECT_ONLY:
			f = cn_cbor_mapput_int(cose->m_protectedMap, key, value,
				CBOR_CONTEXT_PARAM_COMMA & error);
			break;

		case COSE_UNPROTECT_ONLY:
			f = cn_cbor_mapput_int(cose->m_unprotectMap, key, value,
				CBOR_CONTEXT_PARAM_COMMA & error);
			break;

		case COSE_DONT_SEND:
			f = cn_cbor_mapput_int(cose->m_dontSendMap, key, value,
				CBOR_CONTEXT_PARAM_COMMA & error);
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
			break;
	}

	CHECK_CONDITION(f, _MapFromCBOR(error));

errorReturn:
	return f;
}

cn_cbor *_COSE_encode_protected(COSE *pMessage, cose_errback *perr)
{
	cn_cbor *pProtected;
	int cbProtected;
	byte *pbProtected = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pMessage->m_allocContext;
#endif	// USE_CBOR_CONTEXT

	pProtected = cn_cbor_index(pMessage->m_cbor, INDEX_PROTECTED);
	if ((pProtected != NULL) && (pProtected->type != CN_CBOR_INVALID)) {
	errorReturn:
		if (pbProtected != NULL) {
			COSE_FREE(pbProtected, context);
		}
		return pProtected;
	}

	if (pMessage->m_protectedMap->length > 0) {
		cbProtected = cn_cbor_encode_size(pMessage->m_protectedMap);
		pbProtected = (byte *)COSE_CALLOC(cbProtected, 1, context);
		CHECK_CONDITION(pbProtected != NULL, COSE_ERR_OUT_OF_MEMORY);

		CHECK_CONDITION(cn_cbor_encoder_write(pbProtected, 0, cbProtected,
							pMessage->m_protectedMap) == cbProtected,
			COSE_ERR_CBOR);
	}
	else {
		cbProtected = 0;
	}

	pProtected = cn_cbor_data_create2(
		pbProtected, cbProtected, 0, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pProtected != NULL, COSE_ERR_OUT_OF_MEMORY);
	pbProtected = NULL;

	CHECK_CONDITION(_COSE_array_replace(pMessage, pProtected, INDEX_PROTECTED,
						CBOR_CONTEXT_PARAM_COMMA NULL),
		COSE_ERR_CBOR);

	return pProtected;
}

bool _COSE_array_replace(COSE *pMessage,
	cn_cbor *cb_value,
	int index,
	CBOR_CONTEXT_COMMA cn_cbor_errback *errp)
{
	return cn_cbor_array_replace(
		pMessage->m_cbor, cb_value, index, CBOR_CONTEXT_PARAM_COMMA errp);
}

cn_cbor *_COSE_arrayget_int(COSE *pMessage, int index)
{
	return cn_cbor_index(pMessage->m_cbor, index);
}

cose_error _MapFromCBOR(cn_cbor_errback err)
{
	switch (err.err) {
		case CN_CBOR_ERR_INVALID_PARAMETER:
			return COSE_ERR_INVALID_PARAMETER;

		case CN_CBOR_ERR_OUT_OF_MEMORY:
			return COSE_ERR_OUT_OF_MEMORY;

		default:
			return COSE_ERR_CBOR;
	}
}

void _COSE_InsertInList(COSE **rootNode, COSE *newMsg)
{
	if (*rootNode == NULL) {
		*rootNode = newMsg;
		return;
	}

	newMsg->m_handleList = *rootNode;
	*rootNode = newMsg;
	return;
}

bool _COSE_IsInList(const COSE *const rootNode, const COSE *const thisMsg)
{
	if (rootNode == NULL) {
		return false;
	}
	if (thisMsg == NULL) {
		return false;
	}

	for (const COSE *walk = rootNode; walk != NULL; walk = walk->m_handleList) {
		if (walk == thisMsg) {
			return true;
		}
	}
	return false;
}

void _COSE_RemoveFromList(COSE **rootNode, COSE *thisMsg)
{
	if (*rootNode == thisMsg) {
		*rootNode = thisMsg->m_handleList;
		thisMsg->m_handleList = NULL;
		return;
	}

	for (COSE *walk = *rootNode; walk->m_handleList != NULL;
		 walk = walk->m_handleList) {
		if (walk->m_handleList == thisMsg) {
			walk->m_handleList = thisMsg->m_handleList;
			thisMsg->m_handleList = NULL;
			return;
		}
	}
	return;
}

#ifndef NDEBUG
#if INCLUDE_COUNTERSIGNATURE
extern COSE *CountersignRoot;
#endif
#if INCLUDE_SIGN
extern COSE *SignerRoot;
extern COSE *SignRoot;
#endif
#if INCLUDE_SIGN1
extern COSE *Sign1Root;
#endif
#if INCLUDE_ENCRYPT0
extern COSE *EncryptRoot;
#endif
#if INCLUDE_ENCRYPT
extern COSE *EnvelopedRoot;
#endif
#if INCLUDE_ENCRYPT || INCLUDE_MAC
extern COSE *RecipientRoot;
#endif
#if INCLUDE_MAC
extern COSE *MacRoot;
#endif
#if INCLUDE_MAC0
extern COSE *Mac0Root;
#endif

bool AreListsEmpty()
{
	bool fRet = true;
#if INCLUDE_COUNTERSIGNATURE
	fRet &= CountersignRoot == NULL;
#endif
#if INCLUDE_SIGN
	fRet &= SignerRoot == NULL && SignRoot == NULL;
#endif
#if INCLUDE_SIGN1
	fRet &= Sign1Root == NULL;
#endif
#if INCLUDE_ENCRYPT0
	fRet &= EncryptRoot == NULL;
#endif
#if INCLUDE_ENCRYPT
	fRet &= EnvelopedRoot == NULL;
#endif
#if INCLUDE_ENCRYPT || INCLUDE_MAC
	fRet &= RecipientRoot == NULL;
#endif
#if INCLUDE_MAC
	fRet &= MacRoot == NULL;
#endif
#if INCLUDE_MAC0
	fRet &= Mac0Root == NULL;
#endif
	return fRet;
}

#endif
