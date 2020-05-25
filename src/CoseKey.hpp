#pragma once

#include "cose/cose.h"

class COSE_KEY {
   public:
	int m_refCount{0};
	cn_cbor *m_cborKey{nullptr};
	int m_flags{0};
	COSE_KEY *m_nextKey{nullptr};

#ifdef USE_CBOR_CONTEXT
	cn_cbor_context m_allocContext{};
#endif

#ifdef COSE_C_USE_OPENSSL
	EVP_PKEY *m_opensslKey{nullptr};
#endif

#ifdef COSE_C_USE_MBEDTLS
	mbedtls_ecp_keypair *m_mbedtls_keypair {nullptr};
#endif
};
