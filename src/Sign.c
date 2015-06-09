#include <stdlib.h>

#include "cose.h"
#include "cose_int.h"


HCOSE COSE_Decode(const byte * rgbData, int cbData, int * ptype, CBOR_CONTEXT_COMMA cose_errback * errp)
{
	cn_cbor * cbor;
	const cn_cbor * pType = NULL;
	HCOSE h;

	if ((rgbData == NULL) || (ptype == NULL)) {
		if (errp != NULL) errp->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	cbor = (cn_cbor *) cn_cbor_decode(rgbData, cbData, CBOR_CONTEXT_PARAM_COMMA NULL);
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
		h = (HCOSE) _COSE_Encrypt_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA errp);
		if (h == NULL) {
			COSE_FREE(cbor, context);
			return NULL;
		}
		return h;

//	case 2:
//		return (COSE *)COSE_Sign_Init(cbor CBOR_CONTEXT_PARAM);
	}

	goto error;
}

#if 0
COSE_SignMessage * COSE_Sign_Init(const cn_cbor * CBOR_CONTEXT)
{
	COSE_SignMessage * msg;

#ifdef USE_CBOR_CONTEXT
	msg = (COSE_SignMessage *) context->calloc_func(1, sizeof(COSE_SignMessage), context->context);
#else
	msg = (COSE_SignMessage *) calloc(1, sizeof(COSE_SignMessage));
#endif

	msg->m_message.m_flags = 1;
	msg->m_message.m_cbor = (cn_cbor *) msg;

	return msg;
}
#endif
