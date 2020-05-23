#include <stdlib.h>

#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "cose_crypto.h"

COSE_KEY *COSE_KEY::KeysRoot = nullptr;

/*! \private
 * @brief Test if a HCOSE_KEY handle is valid
 *
 *  Internal function to test if a key handle is valid.
 *  This will start returning invalid results and cause the code to
 *  crash if handles are not released before the memory that underlies them
 *  is deallocated.  This is an issue of a block allocator is used since
 *  in that case it is common to allocate memory but never to de-allocate it
 *  and just do that in a single big block.
 *
 *  @param h handle to be validated
 *  @returns result of check
 */

bool COSE_KEY::IsValidKeyHandle(HCOSE_KEY h)
{
	COSE_KEY *p = reinterpret_cast<COSE_KEY *>(h);
	if (KeysRoot == nullptr) {
		return false;
	}
	if (p == nullptr) {
		return false;
	}

	for (const COSE_KEY *walk = KeysRoot; walk != nullptr;
		 walk = walk->m_nextKey) {
		if (walk == p) {
			return true;
		}
	}
	return false;
}

HCOSE_KEY COSE_KEY_FromCbor(cn_cbor *pcborKey,
	CBOR_CONTEXT_COMMA cose_errback *perror)
{
	COSE_KEY *pkey = nullptr;

	pkey = new (std::nothrow, context) COSE_KEY();
	if (pkey == nullptr) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_OUT_OF_MEMORY;
		}
		return nullptr;
	}

	pkey->m_cborKey = pcborKey;

	return reinterpret_cast<HCOSE_KEY>(pkey);
}

COSE_KEY::~COSE_KEY()

{
	if (m_cborKey != nullptr) {
		CN_CBOR_FREE(m_cborKey, &m_allocContext);
	}

	if (KeysRoot == this) {
		KeysRoot = this->m_nextKey;
		this->m_nextKey = nullptr;
		;
	}
	else {
		for (COSE_KEY *walk = KeysRoot; walk->m_nextKey != nullptr;
			 walk = walk->m_nextKey) {
			if (walk->m_nextKey == this) {
				walk->m_nextKey = this->m_nextKey;
				this->m_nextKey = nullptr;
				break;
			}
		}
	}
	if (m_cborKey != nullptr && m_cborKey->parent == nullptr) {
		CN_CBOR_FREE(m_cborKey, &m_allocContext);
	}
}

bool COSE_KEY_Free(HCOSE_KEY h)
{
	COSE_KEY *key = reinterpret_cast<COSE_KEY *>(h);
	if (!COSE_KEY::IsValidKeyHandle(h)) {
		return false;
	}
	key->Release();
	return true;
}

#if defined(COSE_C_USE_OPENSSL) && (OPENSSL_VERSION_NUMBER > 0x10100000L)
HCOSE_KEY COSE_KEY_FromEVP(EVP_PKEY *opensslKey,
	cn_cbor *pcborKey,
	CBOR_CONTEXT_COMMA cose_errback *perror)
{
	COSE_KEY *pkey = new (std::nothrow, context) COSE_KEY();
	if (pkey == nullptr) {
		perror->err = COSE_ERR_OUT_OF_MEMORY;
		return nullptr;
	}

	pkey->m_opensslKey = opensslKey;
	pkey->m_cborKey = pcborKey;
	EVP_PKEY_up_ref(opensslKey);

	return reinterpret_cast<HCOSE_KEY>(pkey);
}
#endif

#ifdef COSE_C_USE_MBEDTLS
HCOSE_KEY COSE_KEY_FromMbedKeypair(mbedtls_ecp_keypair *mbedtls_keypair,
	cn_cbor *pcborKey,
	int flags,
	CBOR_CONTEXT_COMMA cose_errback *perror)
{
	COSE_KEY *pkey = new (std::nothrow, context) COSE_KEY();
	if (pkey == nullptr) {
		perror->err = COSE_ERR_OUT_OF_MEMORY;
		return nullptr;
	}

	pkey->m_mbedtls_keypair = mbedtls_keypair;
	pkey->m_flags = flags;

	return reinterpret_cast<HCOSE_KEY>(pkey);
}

#endif
