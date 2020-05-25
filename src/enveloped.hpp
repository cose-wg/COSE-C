#pragma once

#include "cose/cose.h"
#include "Cose.hpp"

class COSE_RecipientInfo;

class COSE_Enveloped {
   public:
	COSE m_message;	 // The message object
	const byte *pbContent;
	size_t cbContent;
	COSE_RecipientInfo *m_recipientFirst;
};

typedef COSE_Enveloped COSE_Encrypt;

HCOSE_ENVELOPED _COSE_Enveloped_Init_From_Object(cn_cbor *,
	COSE_Enveloped *pIn,
	CBOR_CONTEXT_COMMA cose_errback *errp);
void _COSE_Enveloped_Release(COSE_Enveloped *p);
bool _COSE_Enveloped_decrypt(COSE_Enveloped *pcose,
	COSE_RecipientInfo *pRecip,
	const byte *pbKeyIn,
	size_t cbKeyIn,
	const char *szContext,
	cose_errback *perr);
bool _COSE_Enveloped_encrypt(COSE_Enveloped *pcose,
	const byte *pbKeyIn,
	size_t cbKeyIn,
	const char *szContext,
	cose_errback *perr);
bool _COSE_Enveloped_SetContent(COSE_Enveloped *cose,
	const byte *rgbContent,
	size_t cbContent,
	cose_errback *errp);

HCOSE_ENCRYPT _COSE_Encrypt_Init_From_Object(cn_cbor *,
	COSE_Encrypt *pIn,
	CBOR_CONTEXT_COMMA cose_errback *errp);
void _COSE_Encrypt_Release(COSE_Encrypt *p);
bool _COSE_Encrypt_SetContent(COSE_Encrypt *cose,
	const byte *rgbContent,
	size_t cbContent,
	cose_errback *errp);
bool _COSE_Encrypt_Build_AAD(COSE *pMessage,
	byte **ppbAAD,
	size_t *pcbAAD,
	const char *szContext,
	cose_errback *perr);
