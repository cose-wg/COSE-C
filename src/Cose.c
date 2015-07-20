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
		pobj->m_protectedMap = (cn_cbor *) cn_cbor_decode((const byte *) pmap->v.str, pmap->length, context, &errState);
		if (pobj->m_protectedMap == NULL) {
			if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER; // M00BUG - get error state from errState
			goto setup_error;
		}
	}

	pobj->m_unprotectMap = (cn_cbor *) cn_cbor_mapget_int(pcbor, COSE_Header_Unprotected);
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
	if (pobj->m_ownMsg && (pobj->m_cbor != NULL)) CN_CBOR_FREE(pobj->m_cbor, context);
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

	return p;
}

bool _COSE_map_put(COSE * pCose, int key, cn_cbor * value, int flags, cose_errback * perror)
{
	cn_cbor_context * context = &pCose->m_allocContext;
	cn_cbor_errback error;
	bool f;

	if ((flags & COSE_BOTH) == COSE_BOTH) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	if (perror != NULL) perror->err = COSE_ERR_NONE;
	if (flags & COSE_PROTECT_ONLY) {
		f = cn_cbor_mapput_int(pCose->m_protectedMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
	}
	else {
		f = cn_cbor_mapput_int(pCose->m_unprotectMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
	}
	if (!f && perror != NULL) {
		perror->err = error.err; // M00BUG
	}
	return f;
}
