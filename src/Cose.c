#include <stdlib.h>
#include <memory.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

bool IsValidCOSEHandle(HCOSE h)
{
	COSE_Encrypt * p = (COSE_Encrypt *)h;
	if (p == NULL) return false;
	return true;
}


bool _COSE_Init(COSE_INIT_FLAGS flags, COSE* pobj, int msgType, CBOR_CONTEXT_COMMA cose_errback * perr)
{
		    cn_cbor_errback errState;;

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) pobj->m_allocContext = *context;
#endif

	CHECK_CONDITION((flags & ~(COSE_INIT_FLAGS_DETACHED_CONTENT | COSE_INIT_FLAGS_NO_CBOR_TAG)) == 0, COSE_ERR_INVALID_PARAMETER);

	pobj->m_flags = flags;

	pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	CHECK_CONDITION_CBOR(pobj->m_protectedMap != NULL, errState);

	pobj->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	CHECK_CONDITION_CBOR(pobj->m_dontSendMap != NULL, errState);

	pobj->m_cborRoot = pobj->m_cbor = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	CHECK_CONDITION_CBOR(pobj->m_cbor != NULL, errState);
	pobj->m_ownMsg = 1;

#ifdef TAG_IN_ARRAY
	if (msgType > 0) {
		cn_cbor * cn = cn_cbor_int_create(msgType, CBOR_CONTEXT_PARAM_COMMA &errState);
		CHECK_CONDITION_CBOR(cn != NULL, errState);
		CHECK_CONDITION_CBOR(cn_cbor_array_append(pobj->m_cbor, cn, &errState), errState);
		pobj->m_msgType = msgType;
	}
#else
	pobj->m_msgType = msgType;
#endif

	pobj->m_unprotectMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	CHECK_CONDITION_CBOR(pobj->m_unprotectMap != NULL, errState);
	CHECK_CONDITION_CBOR(_COSE_array_replace(pobj, pobj->m_unprotectMap, INDEX_UNPROTECTED, CBOR_CONTEXT_PARAM_COMMA &errState), errState);
	pobj->m_ownUnprotectedMap = false;

	
	if (!(flags & COSE_INIT_FLAGS_NO_CBOR_TAG)) {
		cn_cbor_errback cbor_error;
		cn_cbor * cn = cn_cbor_tag_create(msgType, pobj->m_cborRoot, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
		pobj->m_cborRoot = cn;
	}

	pobj->m_refCount = 1;

	return true;

errorReturn:
	return false;
}

bool _COSE_Init_From_Object(COSE* pobj, cn_cbor * pcbor, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	const cn_cbor * pmap = NULL;
	cn_cbor_errback errState; // = { 0 };
#ifdef TAG_IN_ARRAY
	cn_cbor * cbor;
#endif // TAG_IN_ARRAY
	cn_cbor_errback cbor_error;

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) pobj->m_allocContext = *context;
#endif
	pobj->m_cborRoot = pcbor;
	pobj->m_cbor = pcbor;

#ifdef TAG_IN_ARRAY
	cbor = cn_cbor_index(pobj->m_cbor, 0);
	CHECK_CONDITION(cbor != NULL, COSE_ERR_INVALID_PARAMETER);

	if (cbor->type == CN_CBOR_UINT) {
		pobj->m_msgType = (int) cbor->v.uint;
	}
#else
	//  Check if we have a tag
	if (pcbor->type == CN_CBOR_TAG) {
		pcbor = pobj->m_cbor = pcbor->first_child;
	}
#endif

	pmap = _COSE_arrayget_int(pobj, INDEX_PROTECTED);

	CHECK_CONDITION(pmap != NULL, COSE_ERR_INVALID_PARAMETER);
	if (pmap != NULL) {
		CHECK_CONDITION(pmap->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

		if (pmap->length == 0) {
			pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
			CHECK_CONDITION(pobj->m_protectedMap, COSE_ERR_OUT_OF_MEMORY);
		}
		else {
			pobj->m_protectedMap = cn_cbor_decode((const byte *)pmap->v.str, pmap->length, CBOR_CONTEXT_PARAM_COMMA &errState);
			CHECK_CONDITION(pobj->m_protectedMap != NULL, COSE_ERR_INVALID_PARAMETER);
		}
	}

	pobj->m_unprotectMap = _COSE_arrayget_int(pobj, INDEX_UNPROTECTED);
	CHECK_CONDITION((pobj->m_unprotectMap != NULL) && (pobj->m_unprotectMap->type == CN_CBOR_MAP), COSE_ERR_INVALID_PARAMETER);
	pobj->m_ownUnprotectedMap = false;

	pobj->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(pobj->m_dontSendMap != NULL, cbor_error);

	pobj->m_ownMsg = true;
	pobj->m_refCount = 1;

	return true;

errorReturn:
	return false;
}

void _COSE_Release(COSE * pobj)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pobj->m_allocContext;
#endif

	if (pobj->m_protectedMap != NULL) CN_CBOR_FREE(pobj->m_protectedMap, context);
	if (pobj->m_ownUnprotectedMap && (pobj->m_unprotectMap != NULL)) CN_CBOR_FREE(pobj->m_unprotectMap, context);
	if (pobj->m_dontSendMap != NULL) CN_CBOR_FREE(pobj->m_dontSendMap, context);
	if (pobj->m_ownMsg && (pobj->m_cborRoot != NULL) && (pobj->m_cborRoot->parent == NULL)) CN_CBOR_FREE(pobj->m_cborRoot, context);
}


HCOSE COSE_Decode(const byte * rgbData, size_t cbData, int * ptype, COSE_object_type struct_type, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	cn_cbor * cbor = NULL;
	cn_cbor * cborRoot = NULL;
#ifdef TAG_IN_ARRAY
	const cn_cbor * pType = NULL;
#endif
	cn_cbor_errback cbor_err;
	HCOSE h;

	CHECK_CONDITION((rgbData != NULL) && (ptype != NULL), COSE_ERR_INVALID_PARAMETER);

	cbor = cborRoot = cn_cbor_decode(rgbData, cbData, CBOR_CONTEXT_PARAM_COMMA &cbor_err);
	CHECK_CONDITION_CBOR(cbor != NULL, cbor_err);

#ifdef TAG_IN_ARRAY
	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

	pType = cn_cbor_index(cbor, 0);
	CHECK_CONDITION(((pType != NULL) && (pType->type == CN_CBOR_UINT)), COSE_ERR_INVALID_PARAMETER);
    *ptype = pType->v.sint;
#else // ! TAG_IN_ARRAY

	if (cbor->type == CN_CBOR_TAG) {
		if (struct_type != 0) {
                    CHECK_CONDITION(struct_type == (COSE_object_type) cbor->v.sint, COSE_ERR_INVALID_PARAMETER);
		}
		else struct_type = cbor->v.uint;

		*ptype = struct_type;

		cbor = cbor->first_child;
	}
	else {
		*ptype = struct_type;
	}

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
#endif // TAG_IN_ARRAY

	switch (*ptype) {
	case COSE_enveloped_object:
		h = (HCOSE)_COSE_Enveloped_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case COSE_sign_object:
		h = (HCOSE)_COSE_Sign_Init_From_Object(cborRoot, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case COSE_sign0_object:
		h = (HCOSE)_COSE_Sign0_Init_From_Object(cborRoot, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case COSE_mac_object:
		h = (HCOSE)_COSE_Mac_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case COSE_mac0_object:
		h = (HCOSE)_COSE_Mac0_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case COSE_encrypt_object:
		h = (HCOSE)_COSE_Encrypt_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	return h;

errorReturn:
	COSE_FREE(cbor, context);
	return NULL;
}

byte RgbDontUse[8 * 1024];   //  Remove this array when we can compute the size of a cbor serialization without this hack.

size_t COSE_Encode(HCOSE msg, byte * rgb, size_t ib, size_t cb)
{
	if (rgb == NULL) return cn_cbor_encoder_write(RgbDontUse, 0, sizeof(RgbDontUse), ((COSE *)msg)->m_cbor) + ib;
	return cn_cbor_encoder_write(rgb, ib, cb, ((COSE*)msg)->m_cbor);
}


cn_cbor * COSE_get_cbor(HCOSE h)
{
	COSE * msg = (COSE *)h;
	if (!IsValidCOSEHandle(h)) return NULL;

	return msg->m_cbor;
}

bool _COSE_SetExternal(COSE * pcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr)
{
	pcose->m_pbExternal = pbExternalData;
	pcose->m_cbExternal = cbExternalData;

	return true;
}


cn_cbor * _COSE_map_get_int(COSE * pcose, int key, int flags, cose_errback * perror)
{
	cn_cbor * p = NULL;

	if (perror != NULL) perror->err = COSE_ERR_NONE;

	if ((pcose->m_protectedMap != NULL) && ((flags & COSE_PROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_int(pcose->m_protectedMap, key);
		if (p != NULL) return p;
	}

	if ((pcose->m_unprotectMap != NULL) && ((flags & COSE_UNPROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_int(pcose->m_unprotectMap, key);
		if (p != NULL) return p;
	}

	if ((pcose->m_dontSendMap != NULL) && ((flags & COSE_DONT_SEND) != 0)) {
		p = cn_cbor_mapget_int(pcose->m_dontSendMap, key);
	}
	return p;
}

cn_cbor * _COSE_map_get_str(COSE * pcose, const char * key, int flags, cose_errback * perror)
{
	cn_cbor * p = NULL;

	if (perror != NULL) perror->err = COSE_ERR_NONE;

	if ((pcose->m_protectedMap != NULL) && ((flags & COSE_PROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_string(pcose->m_protectedMap, key);
		if (p != NULL) return p;
	}

	if ((pcose->m_unprotectMap != NULL) && ((flags & COSE_UNPROTECT_ONLY) != 0)) {
		p = cn_cbor_mapget_string(pcose->m_unprotectMap, key);
	}

	if ((pcose->m_dontSendMap != NULL) && ((flags & COSE_DONT_SEND) != 0)) {
		p = cn_cbor_mapget_string(pcose->m_dontSendMap, key);
	}

	return p;
}

bool _COSE_map_put(COSE * pCose, int key, cn_cbor * value, int flags, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT    
	cn_cbor_context * context = &pCose->m_allocContext;
#endif
	cn_cbor_errback error;
	bool f = false;

	CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_protectedMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_unprotectMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_dontSendMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);

	switch (flags) {
	case COSE_PROTECT_ONLY:
		f = cn_cbor_mapput_int(pCose->m_protectedMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
		break;

	case COSE_UNPROTECT_ONLY:
		f = cn_cbor_mapput_int(pCose->m_unprotectMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
		break;

	case COSE_DONT_SEND:
		if (pCose->m_dontSendMap == NULL) {
			pCose->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &error);
			CHECK_CONDITION(pCose->m_dontSendMap != NULL, COSE_ERR_OUT_OF_MEMORY);
		}
		f = cn_cbor_mapput_int(pCose->m_dontSendMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
		break;

	default:
		FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
		break;
	}

	CHECK_CONDITION(f, _MapFromCBOR(error));

errorReturn:
	return f;
}

byte RgbDontUse3[1024];

cn_cbor * _COSE_encode_protected(COSE * pMessage, cose_errback * perr)
{
	cn_cbor * pProtected;
	int cbProtected;
	byte * pbProtected = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pMessage->m_allocContext;
#endif // USE_CBOR_CONTEXT

#ifdef TAG_IN_ARRAY
	pProtected = cn_cbor_index(pMessage->m_cbor, INDEX_PROTECTED + (pMessage->m_msgType == 0 ? 0 : 1));
#else
	pProtected = cn_cbor_index(pMessage->m_cbor, INDEX_PROTECTED);
#endif
	if ((pProtected != NULL) &&(pProtected->type != CN_CBOR_INVALID)) {
	errorReturn:
		if (pbProtected != NULL) COSE_FREE(pbProtected, context);
		return pProtected;
	}

	if (pMessage->m_protectedMap->length > 0) {
		cbProtected = cn_cbor_encoder_write(RgbDontUse3, 0, sizeof(RgbDontUse3), pMessage->m_protectedMap);
		pbProtected = (byte *)COSE_CALLOC(cbProtected, 1, context);
		CHECK_CONDITION(pbProtected != NULL, COSE_ERR_OUT_OF_MEMORY);

		CHECK_CONDITION(cn_cbor_encoder_write(pbProtected, 0, cbProtected, pMessage->m_protectedMap) == cbProtected, COSE_ERR_CBOR);
	}
	else {
		cbProtected = 0;
	}

	pProtected = cn_cbor_data_create(pbProtected, cbProtected, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(pProtected != NULL, COSE_ERR_OUT_OF_MEMORY);
	pbProtected = NULL;

	CHECK_CONDITION(_COSE_array_replace(pMessage, pProtected, INDEX_PROTECTED, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);

	return pProtected;
}

bool _COSE_array_replace(COSE * pMessage, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback * errp)
{
#ifdef TAG_IN_ARRAY
	if (pMessage->m_msgType != 0) index += 1;
#endif
	return cn_cbor_array_replace(pMessage->m_cbor, cb_value, index, CBOR_CONTEXT_PARAM_COMMA errp);
}

cn_cbor * _COSE_arrayget_int(COSE * pMessage, int index)
{
#ifdef TAG_IN_ARRAY
	if (pMessage->m_msgType != 0) index += 1;
#endif
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

void _COSE_InsertInList(COSE ** root, COSE * newMsg)
{
	if (*root == NULL) {
		*root = newMsg;
		return;
	}

	newMsg->m_handleList = *root;
	*root = newMsg;
	return;
}

bool _COSE_IsInList(COSE * root, COSE * thisMsg)
{
	COSE * walk;

	if (root == NULL) return false;
	if (thisMsg == NULL) return false;

	for (walk = root; walk != NULL; walk = walk->m_handleList) {
		if (walk == thisMsg) return true;		
	}
	return false;
}

void _COSE_RemoveFromList(COSE ** root, COSE * thisMsg)
{
	COSE * walk;

	if (*root == thisMsg) {
		*root = thisMsg->m_handleList;
		thisMsg->m_handleList = NULL;
		return;
	}

	for (walk = *root; walk->m_handleList != NULL; walk = walk->m_handleList) {
		if (walk->m_handleList == thisMsg) {
			walk->m_handleList = thisMsg->m_handleList;
			thisMsg->m_handleList = NULL;
			return;
		}
	}
	return;
}
