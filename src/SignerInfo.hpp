#pragma once

#include "Cose.hpp"

// forward declararion
class COSE_KEY;

class COSE_SignerInfo {
   public:
	COSE m_message;
	COSE_KEY *m_pkey;
	COSE_SignerInfo *m_signerNext;
};

bool _COSE_SignerInfo_Init(COSE_INIT_FLAGS flags,
	COSE_SignerInfo *pcose,
	int msgType,
	CBOR_CONTEXT_COMMA cose_errback *errp);
bool _COSE_Signer_sign(COSE_SignerInfo *pSigner,
	const cn_cbor *pcborBody,
	const cn_cbor *pcborProtected,
	const char *const contextString,
	cose_errback *perr);
COSE_SignerInfo *_COSE_SignerInfo_Init_From_Object(cn_cbor *cbor,
	COSE_SignerInfo *pIn,
	CBOR_CONTEXT_COMMA cose_errback *perr);
bool _COSE_SignerInfo_Release(COSE_SignerInfo *pSigner);
bool _COSE_Signer_validate(COSE_SignerInfo *pSigner,
	const cn_cbor *pbContent,
	const cn_cbor *pbProtected,
	const char *const szContext,
	cose_errback *perr);
