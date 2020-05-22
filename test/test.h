#pragma once

#include <stdbool.h>

#include "cose/cose.h"
#include "context.h"
#include "cose_int.h"

#ifdef USE_CBOR_CONTEXT
extern cn_cbor_context* context;
#define CBOR_CONTEXT_PARAM , context
#define CBOR_CONTEXT_PARAM_COMMA context,
#else
#define CBOR_CONTEXT_PARAM
#define CBOR_CONTEXT_PARAM_COMMA
#endif

//  encrypt.c

bool ValidateEnveloped(const cn_cbor* pControl);
int EncryptMessage();
bool BuildEnvelopedMessage(const cn_cbor* pControl);
bool ValidateEncrypt(const cn_cbor* pControl);
bool BuildEncryptMessage(const cn_cbor* pControl);
void Enveloped_Corners();
void Encrypt_Corners();
void Recipient_Corners();
void CounterSign_Corners();

//  sign.c

bool ValidateSigned(const cn_cbor* pControl);
int SignMessage();
bool BuildSignedMessage(const cn_cbor* pControl);
bool ValidateSign1(const cn_cbor* pControl);
bool BuildSign1Message(const cn_cbor* pControl);
void Sign_Corners();
void Sign1_Corners();

// mac_testc

bool ValidateMAC(const cn_cbor* pControl);
int MacMessage();
bool BuildMacMessage(const cn_cbor* pControl);
bool ValidateMac0(const cn_cbor* pControl);
bool BuildMac0Message(const cn_cbor* pControl);
void MAC_Corners();
void MAC0_Corners();

//  test.c
typedef enum {
	Attributes_MAC_protected = 1,
	Attributes_MAC0_protected,
	Attributes_Recipient_protected,
	Attributes_Enveloped_protected,
	Attributes_Encrypt_protected,
	Attributes_Sign_protected,
	Attributes_Signer_protected,
	Attributes_Sign1_protected,
	Attributes_Countersign_protected,
	Attributes_Countersign1_protected
} whichSet;

extern int CFails;

int MapAlgorithmName(const cn_cbor* p);
byte* GetCBOREncoding(const cn_cbor* pControl, int* pcbEncoded);
// bool SetAttributes(HCOSE hHandle, const cn_cbor * pAttributes, int which,
// bool fPublicKey);
HCOSE_KEY BuildKey(const cn_cbor* pKeyIn, bool fPublicKey);
cn_cbor* BuildCborKey(const cn_cbor* pKeyIn, bool fPublicKey);
byte* FromHex(const char* rgch, int cch);
bool SetSendingAttributes(void* pMsg, const cn_cbor* pIn, int base);
bool SetReceivingAttributes(void* pMsg, const cn_cbor* pIn, int base);
int IsAlgorithmSupported(const cn_cbor* alg);

//
//  Internal macros to make testing easier
//

#define CHECK_RETURN(functionCall, errorReturn, onFailure) \
	{                                                      \
		if (!functionCall)                                 \
			onFailure;                                     \
	}

#define CHECK_FAILURE(functionCall, errorReturn, onFailure) \
	{                                                       \
		bool bReturn = functionCall;                        \
		if (!bReturn) {                                     \
			if (cose_error.err != errorReturn)              \
				onFailure;                                  \
		}                                                   \
		else if (errorReturn != COSE_ERR_NONE)              \
			onFailure;                                      \
	}

#define CHECK_FAILURE_PTR(functionCall, errorReturn, onFailure) \
	{                                                           \
		void* bReturn = functionCall;                           \
		if (bReturn == NULL) {                                  \
			if (cose_error.err != errorReturn)                  \
				onFailure;                                      \
		}                                                       \
		else if (errorReturn != COSE_ERR_NONE)                  \
			onFailure;                                          \
	}

#define Safe_Handle(handleName, freeFunction)          \
	class Safe_##handleName {                          \
		handleName h;                                  \
                                                       \
	   public:                                         \
		Safe_##handleName() { h = NULL; }              \
		Safe_##handleName(handleName hIn) { h = hIn; } \
		~Safe_##handleName() { freeFunction(h); }      \
		handleName Set(handleName hIn)                 \
		{                                              \
			if (h != NULL) {                           \
				freeFunction(h);                       \
			}                                          \
			h = hIn;                                   \
			return hIn;                                \
		}                                              \
		bool IsNull() { return h == NULL; }            \
		HCOSE ToCOSE() { return (HCOSE)h; }            \
		operator handleName() { return h; }            \
		handleName operator=(handleName pIn)           \
		{                                              \
			Set(pIn);                                  \
			return pIn;                                \
		}                                              \
		handleName Transfer(Safe_##handleName* hIn)    \
		{                                              \
			if (h != NULL) {                           \
				freeFunction(h);                       \
			}                                          \
			h = hIn->h;                                \
			hIn->h = NULL;                             \
			return h;                                  \
		}                                              \
		handleName operator=(Safe_##handleName hIn)    \
		{                                              \
			Set(hIn.h);                                \
			return h;                                  \
		}                                              \
		void Clear() { h = NULL; }                     \
		handleName Release()                           \
		{                                              \
			handleName h2 = h;                         \
			h = NULL;                                  \
			return h2;                                 \
		}                                              \
	};

Safe_Handle(HCOSE_ENCRYPT, COSE_Encrypt_Free);
Safe_Handle(HCOSE_ENVELOPED, COSE_Enveloped_Free);
Safe_Handle(HCOSE_RECIPIENT, COSE_Recipient_Free);
Safe_Handle(HCOSE_COUNTERSIGN, COSE_CounterSign_Free);
Safe_Handle(HCOSE_COUNTERSIGN1, COSE_CounterSign1_Free);
Safe_Handle(HCOSE_KEY, COSE_KEY_Free);
Safe_Handle(HCOSE_MAC, COSE_Mac_Free);
Safe_Handle(HCOSE_MAC0, COSE_Mac0_Free);
Safe_Handle(HCOSE_SIGN, COSE_Sign_Free);
Safe_Handle(HCOSE_SIGN1, COSE_Sign1_Free);
Safe_Handle(HCOSE_SIGNER, COSE_Signer_Free);

class Safe_CN_CBOR {
	cn_cbor* p;

   public:
	Safe_CN_CBOR() { p = NULL; }
	Safe_CN_CBOR(cn_cbor* pIn) { p = pIn; }
	~Safe_CN_CBOR() { CN_CBOR_FREE(p, context); };
	cn_cbor* Set(cn_cbor* pIn)
	{
		if (p != NULL) {
			CN_CBOR_FREE(p, context);
		}
		p = pIn;
		return pIn;
	}
	inline bool IsNull() { return p == NULL; }
	inline operator cn_cbor*() { return p; }
	inline void Clear() { p = NULL; }
	inline cn_cbor* operator=(cn_cbor* pIn)
	{
		Set(pIn);
		return pIn;
	}
};
