#include <stdlib.h>

#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "cose_crypto.h"

COSE_KEY *KeysRoot = NULL;

/*! \private
 * @brief Test if a HCOSE_ENVELOPED handle is valid
 *
 *  Internal function to test if a enveloped message handle is valid.
 *  This will start returning invalid results and cause the code to
 *  crash if handles are not released before the memory that underlies them
 *  is deallocated.  This is an issue of a block allocator is used since
 *  in that case it is common to allocate memory but never to de-allocate it
 *  and just do that in a single big block.
 *
 *  @param h handle to be validated
 *  @returns result of check
 */

bool IsValidKeyHandle(HCOSE_KEY h)
{
	COSE_KEY *p = (COSE_KEY*)h;
	if (KeysRoot == NULL) {
		return false;
	}
	if (p == NULL) {
		return false;
	}

	for (const COSE_KEY *walk = KeysRoot; walk != NULL; walk = walk->m_nextKey) {
		if (walk == p) {
			return true;
		}
	}
	return false;
}

HCOSE_KEY COSE_KEY_FromCbor(cn_cbor *pcborKey,
	CBOR_CONTEXT_COMMA cose_errback *perror)
{
	COSE_KEY *pkey = NULL;

	pkey = (COSE_KEY *)COSE_CALLOC(1, sizeof(COSE_KEY), context);

	if (pkey == NULL) {
		if (perror != NULL) {
			perror->err = COSE_ERR_OUT_OF_MEMORY;
		}
		return NULL;
	}

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) {
		pkey->m_allocContext = *context;
	}
#endif
	
	pkey->m_refCount = 1;
	pkey->m_cborKey = pcborKey;

	pkey->m_nextKey = KeysRoot;
	KeysRoot = pkey;
	
	return (HCOSE_KEY)pkey;
}

bool COSE_KEY_Free(HCOSE_KEY h)
{
	COSE_KEY *p = (COSE_KEY *)h;
	if (!IsValidKeyHandle(h)) {
		return false;	
	}

	if (p->m_refCount > 1) {
		p->m_refCount--;
		return true;
	}
	
	if (KeysRoot == p) {
		KeysRoot = p->m_nextKey;
		p->m_nextKey = NULL;;
	}
	else {
		for (COSE_KEY *walk = KeysRoot; walk->m_nextKey != NULL;
			 walk = walk->m_nextKey) {
			if (walk->m_nextKey == p) {
				walk->m_nextKey = p->m_nextKey;
				p->m_nextKey = NULL;
				break;
			}
		}
	}
	
	COSE_FREE(p, &p->m_allocContext);

	return true;
}

#if defined(COSE_C_USE_OPENSSL) && (OPENSSL_VERSION_NUMBER > 0x10100000L)
HCOSE_KEY COSE_KEY_FromEVP(EVP_PKEY * opensslKey, cn_cbor * pcborKey, CBOR_CONTEXT_COMMA cose_errback* perror)
{
	COSE_KEY *pkey = NULL;

	pkey = (COSE_KEY *)COSE_CALLOC(1, sizeof(COSE_KEY), context);

	if (pkey == NULL) {
		perror->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

#ifdef USE_CBOR_CONTEXT
	if (context != NULL) {
		pkey->m_allocContext = *context;
	}
#endif

	pkey->m_refCount = 1;
	pkey->m_cborKey = pcborKey;
	pkey->m_opensslKey = opensslKey;
	EVP_PKEY_up_ref(opensslKey);

	pkey->m_nextKey = KeysRoot;
	KeysRoot = pkey;

	return (HCOSE_KEY)pkey;
}
#endif
