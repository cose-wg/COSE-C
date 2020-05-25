#pragma once

#include "Cose.hpp"

// forward declaration
class COSE_RecipientInfo;

class COSE_MacMessage {
   public:
	COSE m_message;	 // The message object
	COSE_RecipientInfo *m_recipientFirst;
};

typedef COSE_MacMessage COSE_Mac0Message;

HCOSE_MAC _COSE_Mac_Init_From_Object(cn_cbor *,
	COSE_MacMessage *pIn,
	CBOR_CONTEXT_COMMA cose_errback *errp);
bool _COSE_Mac_Release(COSE_MacMessage *p);
bool _COSE_Mac_Build_AAD(COSE *pCose,
	const char *szContext,
	byte **ppbAuthData,
	size_t *pcbAuthData,
	CBOR_CONTEXT_COMMA cose_errback *perr);
bool _COSE_Mac_compute(COSE_MacMessage *pcose,
	const byte *pbKeyIn,
	size_t cbKeyIn,
	const char *szContext,
	cose_errback *perr);
bool _COSE_Mac_validate(COSE_MacMessage *pcose,
	COSE_RecipientInfo *pRecip,
	const byte *pbKeyIn,
	size_t cbKeyIn,
	const char *szContext,
	cose_errback *perr);

//  MAC0 Items

HCOSE_MAC0 _COSE_Mac0_Init_From_Object(cn_cbor *,
	COSE_Mac0Message *pIn,
	CBOR_CONTEXT_COMMA cose_errback *errp);
bool _COSE_Mac0_Release(COSE_Mac0Message *p);