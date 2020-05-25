#pragma once

#include <cose/cose.h>
#include <cn-cbor/cn-cbor.h>

// forward declarations
class COSE_CounterSign;
class COSE_CounterSign1;

class COSE {
   public:
	COSE_INIT_FLAGS m_flags;   //  Not sure what goes here yet
	bool m_ownMsg;			   //  Do I own the pointer @ m_cbor?
	bool m_ownUnprotectedMap;  //  Do I own the pointer @ m_unportectedMap?
	int m_msgType;			   //  What message type is this?
	int m_refCount;			   //  Allocator Reference Counting.
	cn_cbor *m_cbor;
	cn_cbor *m_cborRoot;
	cn_cbor *m_protectedMap;
	cn_cbor *m_unprotectMap;
	cn_cbor *m_dontSendMap;
	const byte *m_pbExternal;
	size_t m_cbExternal;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context m_allocContext;
#endif
	COSE *m_handleList;
#if INCLUDE_COUNTERSIGNATURE
	COSE_CounterSign
		*m_counterSigners;	// Linked list of all counter signatures
#endif
#if INCLUDE_COUNTERSIGNATURE1
	COSE_CounterSign1 *m_counterSign1;
#endif
};

bool _COSE_Init(COSE_INIT_FLAGS flags,
	COSE *pcose,
	int msgType,
	CBOR_CONTEXT_COMMA cose_errback *perr);
bool _COSE_Init_From_Object(COSE *pobj,
	cn_cbor *pcbor,
	CBOR_CONTEXT_COMMA cose_errback *perr);
void _COSE_Release(COSE *pcose);