#pragma once

#include "Cose.hpp"

class COSE_Sign1Message {
   public:
	COSE m_message{};	 // The message object
};

HCOSE_SIGN1 _COSE_Sign1_Init_From_Object(cn_cbor *cbor,
	COSE_Sign1Message *pIn,
	CBOR_CONTEXT_COMMA cose_errback *perr);
void _COSE_Sign1_Release(COSE_Sign1Message *p);
