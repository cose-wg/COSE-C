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
int BuildEnvelopedMessage(const cn_cbor * pControl);
int ValidateEncrypt(const cn_cbor * pControl);
int BuildEncryptMessage(const cn_cbor * pControl);

//  sign.c

int ValidateSigned(const cn_cbor * pControl);
int SignMessage();
int BuildSignedMessage(const cn_cbor * pControl);
int ValidateSign0(const cn_cbor * pControl);
int BuildSign0Message(const cn_cbor * pControl);

// mac_testc

int ValidateMAC(const cn_cbor * pControl);
int MacMessage();
int BuildMacMessage(const cn_cbor * pControl);
int ValidateMac0(const cn_cbor * pControl);
int BuildMac0Message(const cn_cbor * pControl);
void MAC_Corners();
void MAC0_Corners();

#ifdef USE_CBOR_CONTEXT
//  context.c
extern cn_cbor_context * CreateContext(unsigned int iFailPoint);
void FreeContext(cn_cbor_context* pContext);
#endif


//  test.c
enum {
	Attributes_MAC_protected=1,
	Attributes_MAC_unprotected,
	Attributes_MAC_unsent,
	Attributes_MAC0_protected,
	Attributes_MAC0_unprotected,
	Attributes_MAC0_unsent,
	Attributes_Recipient_protected,
	Attributes_Recipient_unprotected,
	Attributes_Recipient_unsent,
	Attributes_Enveloped_protected,
	Attributes_Enveloped_unprotected,
	Attributes_Enveloped_unsent,
	Attributes_Encrypt_protected,
	Attributes_Encrypt_unprotected,
	Attributes_Encrypt_unsent,
	Attributes_Sign_protected,
	Attributes_Sign_unprotected,
	Attributes_Sign_unsent,
	Attributes_Signer_protected,
	Attributes_Signer_unprotected,
	Attributes_Signer_unsent,
	Attributes_Sign0_protected,
	Attributes_Sign0_unprotected,
	Attributes_Sign0_unsent,
} whichSet;

extern int CFails;

int MapAlgorithmName(const cn_cbor * p);
byte * GetCBOREncoding(const cn_cbor * pControl, int * pcbEncoded);
bool SetAttributes(HCOSE hHandle, const cn_cbor * pAttributes, int which);
cn_cbor * BuildKey(const cn_cbor * pKeyIn);
