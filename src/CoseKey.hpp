#pragma once

#include "cose/cose.h"

class COSE_KEY {
   public:
	int m_refCount;
	cn_cbor *m_cborKey;
	int m_flags;
COSE_KEY *m_nextKey;

#ifdef USE_CBOR_CONTEXT
	cn_cbor_context m_allocContext;
#endif

#ifdef COSE_C_USE_OPENSSL
	EVP_PKEY *m_opensslKey;
#endif

#ifdef COSE_C_USE_MBEDTLS
	mbedtls_ecp_keypair *m_mbedtls_keypair;
#endif

};
