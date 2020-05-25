#pragma once

#include "Cose.hpp"

// forward declaration
class COSE_SignerInfo;

class COSE_SignMessage {
   public:
	// The message object
	COSE m_message{};
	COSE_SignerInfo *m_signerFirst{nullptr};
};

HCOSE_SIGN _COSE_Sign_Init_From_Object(cn_cbor *,
	COSE_SignMessage *pIn,
	CBOR_CONTEXT_COMMA cose_errback *errp);
void _COSE_Sign_Release(COSE_SignMessage *p);
