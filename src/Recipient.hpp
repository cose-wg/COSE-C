#pragma once

#include "Enveloped.hpp"

// forward declaration
class COSE_KEY;

class COSE_RecipientInfo {
   public:
	COSE_Enveloped m_encrypt{};
	COSE_RecipientInfo *m_recipientNext{nullptr};
	COSE_KEY *m_pkey{nullptr};
	COSE_KEY *m_pkeyStatic{nullptr};
};

COSE_RecipientInfo *_COSE_Recipient_Init_From_Object(cn_cbor *,
	CBOR_CONTEXT_COMMA cose_errback *errp);
void _COSE_Recipient_Free(COSE_RecipientInfo *);
bool _COSE_Recipient_decrypt(COSE_RecipientInfo *pRecip,
	COSE_RecipientInfo *pRecipUse,
	int algIn,
	size_t cbitKey,
	byte *pbKey,
	cose_errback *errp);
bool _COSE_Recipient_encrypt(COSE_RecipientInfo *pRecipient,
	const byte *pbContent,
	size_t cbContent,
	cose_errback *perr);
byte *_COSE_RecipientInfo_generateKey(COSE_RecipientInfo *pRecipient,
	int algIn,
	size_t cbitKeySize,
	cose_errback *perr);
