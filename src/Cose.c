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


bool _COSE_Init(COSE* pobj, int msgType, CBOR_CONTEXT_COMMA cose_errback * perr)
{
        cn_cbor_errback errState;  // = { 0 };

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) pobj->m_allocContext = *context;
#endif

	pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_protectedMap == NULL) {
	error_setup:
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		_COSE_Release(pobj);
		return false;
	}

	pobj->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_dontSendMap == NULL) goto error_setup;

#ifdef USE_ARRAY
	pobj->m_cbor = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &errState);
#else
	pobj->m_cbor = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
#endif
	if (pobj->m_cbor == NULL) goto error_setup;
	pobj->m_ownMsg = 1;

	if (msgType > 0) {
		cn_cbor * cn = cn_cbor_int_create(msgType, CBOR_CONTEXT_PARAM_COMMA NULL);
		CHECK_CONDITION(cn != NULL, COSE_ERR_OUT_OF_MEMORY);
		CHECK_CONDITION(cn_cbor_array_append(pobj->m_cbor, cn, NULL), COSE_ERR_OUT_OF_MEMORY);
		pobj->m_msgType = msgType;
	}

	pobj->m_unprotectMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_unprotectMap == NULL) goto error_setup;
	CHECK_CONDITION(_COSE_array_replace(pobj, pobj->m_unprotectMap, INDEX_UNPROTECTED, CBOR_CONTEXT_PARAM_COMMA &errState), COSE_ERR_OUT_OF_MEMORY);
	pobj->m_ownUnprotectedMap = false;

	return true;
}

bool _COSE_Init_From_Object(COSE* pobj, cn_cbor * pcbor, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	const cn_cbor * pmap = NULL;
	cn_cbor_errback errState = { 0 };
	cn_cbor * cbor;

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) pobj->m_allocContext = *context;
#endif
	pobj->m_cbor = pcbor;

	cbor = cn_cbor_index(pobj->m_cbor, 0);
	if (cbor->type == CN_CBOR_UINT) {
		pobj->m_msgType = cbor->v.uint;
	}

#ifdef USE_ARRAY
	pmap = _COSE_arrayget_int(pobj, INDEX_PROTECTED);
#else
	pmap = cn_cbor_mapget_int(pcbor, COSE_Header_Protected);
#endif
	if (pmap != NULL) {
		CHECK_CONDITION(pmap->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

		if (pmap->length == 0) {
			pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
		}
		else {
			pobj->m_protectedMap = cn_cbor_decode((const byte *)pmap->v.str, pmap->length, context, &errState);
			CHECK_CONDITION(pobj->m_protectedMap != NULL, COSE_ERR_INVALID_PARAMETER);
		}
	}

#ifdef USE_ARRAY
	pobj->m_unprotectMap = _COSE_arrayget_int(pobj, INDEX_UNPROTECTED);
#else
	pobj->m_unprotectMap = cn_cbor_mapget_int(pcbor, COSE_Header_Unprotected);
#endif
	CHECK_CONDITION(pobj->m_unprotectMap->type == CN_CBOR_MAP, COSE_ERR_INVALID_PARAMETER);
	pobj->m_ownUnprotectedMap = false;

	pobj->m_ownMsg = true;

	return true;

errorReturn:
	_COSE_Release(pobj);
	return false;
}

void _COSE_Release(COSE * pobj)
{
	cn_cbor_context * context = &pobj->m_allocContext;

	if (pobj->m_protectedMap != NULL) CN_CBOR_FREE(pobj->m_protectedMap, context);
	if (pobj->m_ownUnprotectedMap && (pobj->m_unprotectMap != NULL)) CN_CBOR_FREE(pobj->m_unprotectMap, context);
	if (pobj->m_dontSendMap != NULL) CN_CBOR_FREE(pobj->m_dontSendMap, context);
	if (pobj->m_ownMsg && (pobj->m_cbor != NULL)) CN_CBOR_FREE(pobj->m_cbor, context);
}


HCOSE COSE_Decode(const byte * rgbData, int cbData, int * ptype, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	cn_cbor * cbor = NULL;
	const cn_cbor * pType = NULL;
	HCOSE h;

	if ((rgbData == NULL) || (ptype == NULL)) {
		goto error;
	}

	cbor = cn_cbor_decode(rgbData, cbData, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(cbor != NULL, COSE_ERR_CBOR);

#ifdef USE_ARRAY
	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
#else
	if (cbor->type != CN_CBOR_MAP) {
	error:
		COSE_FREE(cbor, context);
		if (errp != NULL) errp->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}
#endif

#ifdef USE_ARRAY
	pType = cn_cbor_index(cbor, 0);
#else
	pType = cn_cbor_mapget_int(cbor, COSE_Header_Type);
#endif
	CHECK_CONDITION(((pType != NULL) && (pType->type == CN_CBOR_UINT)), COSE_ERR_INVALID_PARAMETER);

	switch (pType->v.sint) {
	case MSG_TYPE_ENCRYPT:
		h = (HCOSE)_COSE_Encrypt_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case MSG_TYPE_SIGN:
		h = (HCOSE)_COSE_Sign_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	case MSG_TYPE_MAC:
		h = (HCOSE)_COSE_Mac_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (h == NULL) {
			goto errorReturn;
		}
		break;

	default:
		FAIL_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
	}

	return h;

error:
	if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
errorReturn:
	COSE_FREE(cbor, context);
	return NULL;
}

cn_cbor * COSE_get_cbor(HCOSE h)
{
	COSE * msg = (COSE *)h;
	if (!IsValidCOSEHandle(h)) return NULL;

	return msg->m_cbor;
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
	cn_cbor_context * context = &pCose->m_allocContext;
	cn_cbor_errback error;
	bool f;

	if ((flags & COSE_BOTH) == COSE_BOTH) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
	errorReturn:
		return false;
	}

	if (perr != NULL) perr->err = COSE_ERR_NONE;

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
		FAIL_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
		break;
	}

	CHECK_CONDITION(f, error.err);

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

#ifdef USE_ARRAY
	pProtected = cn_cbor_index(pMessage->m_cbor, INDEX_PROTECTED + (pMessage->m_msgType == 0 ? 0 : 1));
#else
	pProtected = cn_cbor_mapget_int(pMessage->m_cbor, COSE_Header_Protected);
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

#ifdef USE_ARRAY
	CHECK_CONDITION(_COSE_array_replace(pMessage, pProtected, INDEX_PROTECTED, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
#else
	CHECK_CONDITION(cn_cbor_mapput_int(pMessage->m_cbor, COSE_Header_Protected, pProtected, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);
#endif

	return pProtected;
}

bool _COSE_array_replace(COSE * pMessage, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback * errp)
{
	if (pMessage->m_msgType != 0) index += 1;
	return cn_cbor_array_replace(pMessage->m_cbor, cb_value, index, CBOR_CONTEXT_PARAM_COMMA errp);
}

cn_cbor * _COSE_arrayget_int(COSE * pMessage, int index)
{
	if (pMessage->m_msgType != 0) index += 1;
	return cn_cbor_index(pMessage->m_cbor, index);
}
