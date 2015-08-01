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


bool _COSE_Init(COSE* pobj, CBOR_CONTEXT_COMMA cose_errback * perror)
{
	cn_cbor_errback errState = { 0 };

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) pobj->m_allocContext = *context;
#endif

	pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_protectedMap == NULL) {
	error_setup:
		_COSE_Release( pobj);
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
return false;
	}

	pobj->m_unprotectMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_unprotectMap == NULL) goto error_setup;
	pobj->m_ownUnprotectedMap = true;

	pobj->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_dontSendMap == NULL) goto error_setup;

	pobj->m_cbor = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
	if (pobj->m_cbor == NULL) goto error_setup;
	pobj->m_ownMsg = true;

	return true;
}

bool _COSE_Init_From_Object(COSE* pobj, cn_cbor * pcbor, CBOR_CONTEXT_COMMA cose_errback * perror)
{
	const cn_cbor * pmap = NULL;
	cn_cbor_errback errState = { 0 };

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) pobj->m_allocContext = *context;
#endif

	pmap = cn_cbor_mapget_int(pcbor, COSE_Header_Protected);
	if (pmap != NULL) {
		if (pmap->type != CN_CBOR_BYTES) {
			if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		setup_error:
			_COSE_Release(pobj);
			return false;
		}
		pobj->m_protectedMap = (cn_cbor *)cn_cbor_decode((const byte *)pmap->v.str, pmap->length, context, &errState);
		if (pobj->m_protectedMap == NULL) {
			if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER; // M00BUG - get error state from errState
			goto setup_error;
		}
	}

	pobj->m_unprotectMap = (cn_cbor *)cn_cbor_mapget_int(pcbor, COSE_Header_Unprotected);
	pobj->m_ownUnprotectedMap = false;

	pobj->m_cbor = pcbor;
	pobj->m_ownMsg = true;

	return true;
}

void _COSE_Release(COSE * pobj)
{
	cn_cbor_context * context = &pobj->m_allocContext;

	if (pobj->m_protectedMap != NULL) CN_CBOR_FREE(pobj->m_protectedMap, context);
	if (pobj->m_ownUnprotectedMap && (pobj->m_unprotectMap != NULL)) CN_CBOR_FREE(pobj->m_unprotectMap, context);
	if (pobj->m_dontSendMap != NULL) CN_CBOR_FREE(pobj->m_dontSendMap, context);
	if (pobj->m_ownMsg && (pobj->m_cbor != NULL)) CN_CBOR_FREE(pobj->m_cbor, context);
}


HCOSE COSE_Decode(const byte * rgbData, int cbData, int * ptype, CBOR_CONTEXT_COMMA cose_errback * errp)
{
	cn_cbor * cbor;
	const cn_cbor * pType = NULL;
	HCOSE h;

	if ((rgbData == NULL) || (ptype == NULL)) {
		if (errp != NULL) errp->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	cbor = (cn_cbor *)cn_cbor_decode(rgbData, cbData, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (cbor == NULL) {
		if (errp != NULL) errp->err = COSE_ERR_CBOR;
		return NULL;
	}

	if (cbor->type != CN_CBOR_MAP) {
	error:
		COSE_FREE(cbor, context);
		if (errp != NULL) errp->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	pType = cn_cbor_mapget_int(cbor, COSE_Header_Type);
	if ((pType == NULL) || (pType->type != CN_CBOR_UINT)) goto error;

	switch (pType->v.sint) {
	case 1:
		h = (HCOSE)_COSE_Encrypt_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA errp);
		if (h == NULL) {
			COSE_FREE(cbor, context);
			return NULL;
		}
		return h;

	case 2:
		h = (HCOSE)_COSE_Sign_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA errp);
		if (h == NULL) {
			COSE_FREE(cbor, context);
			return NULL;
		}
		return h;
	}

	goto error;
}

cn_cbor * COSE_get_cbor(HCOSE h)
{
	COSE * msg = (COSE *)h;
	if (!IsValidCOSEHandle(h)) return NULL;

	return msg->m_cbor;
}

const cn_cbor * _COSE_map_get_int(COSE * pcose, int key, int flags, cose_errback * perror)
{
	const cn_cbor * p = NULL;

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

const cn_cbor * _COSE_map_get_str(COSE * pcose, const char * key, int flags, cose_errback * perror)
{
	const cn_cbor * p = NULL;

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
		CHECK_CONDITION(false, COSE_ERR_INVALID_PARAMETER);
		break;
	}

	CHECK_CONDITION(f, error.err);

	return f;
}
