#ifndef _countof
#define _countof(x) (sizeof(x)/sizeof(x[0]))
#endif

#ifdef USE_CBOR_CONTEXT
cn_cbor_context * allocator;
#define CBOR_CONTEXT_PARAM , allocator
#define CBOR_CONTEXT_PARAM_COMMA allocator,
#else
#define CBOR_CONTEXT_PARAM
#define CBOR_CONTEXT_PARAM_COMMA
#endif

//  encrypt.c

int ValidateEnveloped(const cn_cbor * pControl);
int EncryptMessage();

//  test.c
enum {
	Attributes_MAC_protected=1,
	Attributes_MAC_unprotected,
	Attributes_Recipient_protected,
	Attributes_Recipient_unprotected,
} whichSet;

int MapAlgorithmName(const cn_cbor * p);
cn_cbor * cn_cbor_clone(const cn_cbor * pIn);
byte * GetCBOREncoding(const cn_cbor * pControl, int * pcbEncoded);
bool SetAttributes(HCOSE hHandle, const cn_cbor * pAttributes, int which);
cn_cbor * BuildKey(const cn_cbor * pKeyIn);
