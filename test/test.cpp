// test.c : Defines the entry point for the console application.
//

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose/cose.h>
#include <cose/cose_configure.h>
#include <cn-cbor/cn-cbor.h>
#include <assert.h>
#include <cose_int.h>

#ifndef _MSC_VER
#include <dirent.h>
#else
#include <windows.h>
#endif

#include "json.h"
#include "test.h"

#ifdef COSE_C_USE_OPENSSL
#include <openssl/ec.h>
#endif

#ifdef COSE_C_USE_MBEDTLS
#include <mbedtls/ecp.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#endif

#ifdef USE_CBOR_CONTEXT
cn_cbor_context* context;
#endif

int CFails = 0;
int KeyFormat = 1;

typedef struct _NameMap {
	const char* sz;
	int i;
} NameMap;

NameMap RgAlgorithmNames[48] = {
	{"HS256", COSE_Algorithm_HMAC_256_256},
	{"HS256/64", COSE_Algorithm_HMAC_256_64},
	{"HS384", COSE_Algorithm_HMAC_384_384},
	{"HS512", COSE_Algorithm_HMAC_512_512},
	{"direct", COSE_Algorithm_Direct},
	{"AES-MAC-128/64", COSE_Algorithm_CBC_MAC_128_64},
	{"AES-MAC-256/64", COSE_Algorithm_CBC_MAC_256_64},
	{"AES-MAC-128/128", COSE_Algorithm_CBC_MAC_128_128},
	{"AES-MAC-256/128", COSE_Algorithm_CBC_MAC_256_128},
	{"A128KW", COSE_Algorithm_AES_KW_128},
	{"A192KW", COSE_Algorithm_AES_KW_192},
	{"A256KW", COSE_Algorithm_AES_KW_256},
	{"A128GCM", COSE_Algorithm_AES_GCM_128},
	{"A192GCM", COSE_Algorithm_AES_GCM_192},
	{"A256GCM", COSE_Algorithm_AES_GCM_256},
	{"AES-CCM-16-128/64", COSE_Algorithm_AES_CCM_16_64_128},
	{"AES-CCM-16-256/64", COSE_Algorithm_AES_CCM_16_64_256},
	{"AES-CCM-16-128/128", COSE_Algorithm_AES_CCM_16_128_128},
	{"AES-CCM-16-256/128", COSE_Algorithm_AES_CCM_16_128_256},
	{"AES-CCM-64-128/64", COSE_Algorithm_AES_CCM_64_64_128},
	{"AES-CCM-64-256/64", COSE_Algorithm_AES_CCM_64_64_256},
	{"AES-CCM-64-128/128", COSE_Algorithm_AES_CCM_64_128_128},
	{"AES-CCM-64-256/128", COSE_Algorithm_AES_CCM_64_128_256},
	{"ES256", COSE_Algorithm_ECDSA_SHA_256},
	{"ES384", COSE_Algorithm_ECDSA_SHA_384},
	{"ES512", COSE_Algorithm_ECDSA_SHA_512},
	{"HKDF-HMAC-SHA-256", COSE_Algorithm_Direct_HKDF_HMAC_SHA_256},
	{"HKDF-HMAC-SHA-512", COSE_Algorithm_Direct_HKDF_HMAC_SHA_512},
	{"HKDF-AES-128", COSE_Algorithm_Direct_HKDF_AES_128},
	{"HKDF-AES-256", COSE_Algorithm_Direct_HKDF_AES_256},
	{"ECDH-ES", COSE_Algorithm_ECDH_ES_HKDF_256},
	{"ECDH-ES-512", COSE_Algorithm_ECDH_ES_HKDF_512},
	{"ECDH-SS", COSE_Algorithm_ECDH_SS_HKDF_256},
	{"ECDH-SS-256", COSE_Algorithm_ECDH_SS_HKDF_256},
	{"ECDH-SS-512", COSE_Algorithm_ECDH_SS_HKDF_512},
	{"ECDH-ES+A128KW", COSE_Algorithm_ECDH_ES_A128KW},
	{"ECDH-ES+A192KW", COSE_Algorithm_ECDH_ES_A192KW},
	{"ECDH-ES+A256KW", COSE_Algorithm_ECDH_ES_A256KW},
	{"ECDH-SS+A128KW", COSE_Algorithm_ECDH_SS_A128KW},
	{"ECDH-SS+A192KW", COSE_Algorithm_ECDH_SS_A192KW},
	{"ECDH-SS+A256KW", COSE_Algorithm_ECDH_SS_A256KW},
	{"ECDH-ES-A128KW", COSE_Algorithm_ECDH_ES_A128KW},
	{"ECDH-ES-A192KW", COSE_Algorithm_ECDH_ES_A192KW},
	{"ECDH-ES-A256KW", COSE_Algorithm_ECDH_ES_A256KW},
	{"ECDH-SS-A128KW", COSE_Algorithm_ECDH_SS_A128KW},
	{"ECDH-SS-A192KW", COSE_Algorithm_ECDH_SS_A192KW},
	{"ECDH-SS-A256KW", COSE_Algorithm_ECDH_SS_A256KW},
	{"EdDSA", COSE_Algorithm_EdDSA},
};

NameMap RgCurveNames[7] = {{"P-256", 1}, {"P-384", 2}, {"P-521", 3},
	{"X25519", 4}, {"X448", 5}, {"Ed25519", 6}, {"Ed448", 7}};

int MapName(const cn_cbor* p, NameMap* rgMap, unsigned int cMap)
{
	for (unsigned int i = 0; i < cMap; i++) {
		if (strcmp(rgMap[i].sz, p->v.str) == 0) {
			return rgMap[i].i;
		}
	}

	assert(false);

	return 0;
}

int MapAlgorithmName(const cn_cbor* p)
{
	return MapName(p, RgAlgorithmNames, _countof(RgAlgorithmNames));
}

byte fromHex(char c)
{
	if (('0' <= c) && (c <= '9')) {
		return c - '0';
	}
	if (('A' <= c) && (c <= 'F')) {
		return c - 'A' + 10;
	}
	if (('a' <= c) && (c <= 'f')) {
		return c - 'a' + 10;
	}
	fprintf(stderr, "Invalid hex");
	exit(1);
}

byte* FromHex(const char* rgch, int cch)
{
	// M00BUG - Why is this using malloc?  It does not get freed anyplace.
	byte* pb = (byte*)malloc(cch / 2);
	const char* pb2 = rgch;

	for (int i = 0; i < cch; i += 2) {
		pb[i / 2] = fromHex(pb2[i]) * 16 + fromHex(pb2[i + 1]);
	}

	return pb;
}

int IsAlgorithmSupported(const cn_cbor* alg)
{
	//  Pretend we support any algorithm which is not an integer - this is a
	//  fail test case

	if ((alg->type != CN_CBOR_INT) && (alg->type != CN_CBOR_UINT)) {
		return true;
	}
	switch (alg->v.sint) {
		default:
			return false;

#ifdef USE_AES_CBC_MAC_128_64
		case COSE_Algorithm_CBC_MAC_128_64:
#endif
#ifdef USE_AES_CBC_MAC_128_128
		case COSE_Algorithm_CBC_MAC_128_128:
#endif
#ifdef USE_AES_CBC_MAC_256_64
		case COSE_Algorithm_CBC_MAC_256_64:
#endif
#ifdef USE_AES_CBC_MAC_256_128
		case COSE_Algorithm_CBC_MAC_256_128:
#endif
#ifdef USE_AES_CCM_16_64_128
		case COSE_Algorithm_AES_CCM_16_64_128:
#endif
#ifdef USE_AES_CCM_16_64_256
		case COSE_Algorithm_AES_CCM_16_64_256:
#endif
#ifdef USE_AES_CCM_64_64_128
		case COSE_Algorithm_AES_CCM_64_64_128:
#endif
#ifdef USE_AES_CCM_64_64_256
		case COSE_Algorithm_AES_CCM_64_64_256:
#endif
#ifdef USE_AES_CCM_16_128_128
		case COSE_Algorithm_AES_CCM_16_128_128:
#endif
#ifdef USE_AES_CCM_16_128_256
		case COSE_Algorithm_AES_CCM_16_128_256:
#endif
#ifdef USE_AES_CCM_64_128_128
		case COSE_Algorithm_AES_CCM_64_128_128:
#endif
#ifdef USE_AES_CCM_64_128_256
		case COSE_Algorithm_AES_CCM_64_128_256:
#endif
#ifdef USE_AES_GCM_128
		case COSE_Algorithm_AES_GCM_128:
#endif
#ifdef USE_AES_GCM_192
		case COSE_Algorithm_AES_GCM_192:
#endif
#ifdef USE_AES_GCM_256
		case COSE_Algorithm_AES_GCM_256:
#endif
#ifdef USE_AES_KW_128
		case COSE_Algorithm_AES_KW_128:
#endif
#ifdef USE_AES_KW_192
		case COSE_Algorithm_AES_KW_192:
#endif
#ifdef USE_AES_KW_256
		case COSE_Algorithm_AES_KW_256:
#endif
#ifdef USE_Direct_HKDF_AES_128
		case COSE_Algorithm_Direct_HKDF_AES_128:
#endif
#ifdef USE_Direct_HKDF_AES_256
		case COSE_Algorithm_Direct_HKDF_AES_256:
#endif
#ifdef USE_Direct_HKDF_HMAC_SHA_256
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
#endif
#ifdef USE_Direct_HKDF_HMAC_SHA_512
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
#endif
#ifdef USE_ECDH_ES_A128KW
		case COSE_Algorithm_ECDH_ES_A128KW:
#endif
#ifdef USE_ECDH_ES_A192KW
		case COSE_Algorithm_ECDH_ES_A192KW:
#endif
#ifdef USE_ECDH_ES_A256KW
		case COSE_Algorithm_ECDH_ES_A256KW:
#endif
#ifdef USE_ECDH_ES_HKDF_256
		case COSE_Algorithm_ECDH_ES_HKDF_256:
#endif
#ifdef USE_ECDH_ES_HKDF_512
		case COSE_Algorithm_ECDH_ES_HKDF_512:
#endif
#ifdef USE_ECDH_SS_A128KW
		case COSE_Algorithm_ECDH_SS_A128KW:
#endif
#ifdef USE_ECDH_SS_A192KW
		case COSE_Algorithm_ECDH_SS_A192KW:
#endif
#ifdef USE_ECDH_SS_A256KW
		case COSE_Algorithm_ECDH_SS_A256KW:
#endif
#ifdef USE_ECDH_SS_HKDF_256
		case COSE_Algorithm_ECDH_SS_HKDF_256:
#endif
#ifdef USE_ECDH_SS_HKDF_512
		case COSE_Algorithm_ECDH_SS_HKDF_512:
#endif
#ifdef USE_ECDSA_SHA_256
		case COSE_Algorithm_ECDSA_SHA_256:
#endif
#ifdef USE_ECDSA_SHA_384
		case COSE_Algorithm_ECDSA_SHA_384:
#endif
#ifdef USE_ECDSA_SHA_512
		case COSE_Algorithm_ECDSA_SHA_512:
#endif
#ifdef USE_HMAC_256_64
		case COSE_Algorithm_HMAC_256_64:
#endif
#ifdef USE_HMAC_256_256
		case COSE_Algorithm_HMAC_256_256:
#endif
#ifdef USE_HMAC_384_384
		case COSE_Algorithm_HMAC_384_384:
#endif
#ifdef USE_HMAC_512_512
		case COSE_Algorithm_HMAC_512_512:
#endif
#ifdef USE_EDDSA
		case COSE_Algorithm_EdDSA:
#endif
		case COSE_Algorithm_Direct:
		case -999:	// Unsupported algorithm for testing.
			return true;
	}
}

byte* GetCBOREncoding(const cn_cbor* pControl, int* pcbEncoded)
{
	const cn_cbor* pOutputs = cn_cbor_mapget_string(pControl, "output");
	byte* pb = nullptr;
	const byte* pb2;
	size_t i;

	if ((pOutputs == nullptr) || (pOutputs->type != CN_CBOR_MAP)) {
		fprintf(stderr, "Invalid output\n");
		exit(1);
	}

	const cn_cbor* pCBOR = cn_cbor_mapget_string(pOutputs, "cbor");
	if ((pCBOR == nullptr) || (pCBOR->type != CN_CBOR_TEXT)) {
		fprintf(stderr, "Invalid cbor object");
		exit(1);
	}

	pb = static_cast<byte*>(malloc(pCBOR->length / 2));
	pb2 = pCBOR->v.bytes;

	for (i = 0; i < pCBOR->length; i += 2) {
		pb[i / 2] = fromHex(pb2[i]) * 16 + fromHex(pb2[i + 1]);
	}

	*pcbEncoded = (int)(pCBOR->length / 2);
	return pb;
}

#define OPERATION_NONE 0
#define OPERATION_BASE64 1
#define OPERATION_IGNORE 2
#define OPERATION_STRING 3
#define OPERATION_HEX 4

struct {
	const char* szKey;
	int kty;
	int operation;
	int keyNew;
} RgStringKeys[12] = {{"kty", 0, OPERATION_IGNORE, COSE_Key_Type},
	{"kid", 0, OPERATION_NONE, COSE_Key_ID},
	{"crv", 2, OPERATION_STRING, COSE_Key_EC2_Curve},
	{"x", 2, OPERATION_BASE64, COSE_Key_EC2_X},
	{"y", 2, OPERATION_BASE64, COSE_Key_EC2_Y}, {"d", 2, OPERATION_BASE64, -4},
	{"k", 4, OPERATION_BASE64, -1},
	{"crv", COSE_Key_Type_OKP, OPERATION_STRING, COSE_Key_OPK_Curve},
	{"x_hex", COSE_Key_Type_OKP, OPERATION_HEX, COSE_Key_OPK_X},
	{"x", COSE_Key_Type_OKP, OPERATION_BASE64, COSE_Key_OPK_X},
	{"d_hex", COSE_Key_Type_OKP, OPERATION_HEX, -4},
	{"d", COSE_Key_Type_OKP, OPERATION_BASE64, -4}};

bool SetAttributes(HCOSE hHandle,
	const cn_cbor* pAttributes,
	int which,
	int msgType,
	bool fPublicKey)
{
	int keyNew = 0;
	bool fRet = true;

	if (pAttributes == nullptr) {
		return true;
	}
	if (pAttributes->type != CN_CBOR_MAP) {
		return false;
	}

	for (const cn_cbor* pKey = pAttributes->first_child; pKey != nullptr;
		 pKey = pKey->next->next) {
		Safe_CN_CBOR pValueNew = nullptr;
		const cn_cbor* pValue = pKey->next;

		if (pKey->type != CN_CBOR_TEXT) {
			return false;
		}

		if (strcmp(pKey->v.str, "alg") == 0) {
			keyNew = COSE_Header_Algorithm;
			pValueNew = cn_cbor_int_create(
				MapAlgorithmName(pValue), CBOR_CONTEXT_PARAM_COMMA nullptr);
		}
		else if (strcmp(pKey->v.str, "ctyp") == 0) {
			keyNew = COSE_Header_Content_Type;
			pValueNew = cn_cbor_clone(pValue, CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else if (strcmp(pKey->v.str, "IV_hex") == 0) {
			keyNew = COSE_Header_IV;
			pValueNew =
				cn_cbor_data_create(FromHex(pValue->v.str, (int)pValue->length),
					(int)pValue->length / 2, CBOR_CONTEXT_PARAM_COMMA nullptr);
		}
		else if (strcmp(pKey->v.str, "apu_id") == 0) {
			keyNew = COSE_Header_KDF_U_name;
			pValueNew = cn_cbor_data_create(pValue->v.bytes,
				(int)pValue->length, CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else if (strcmp(pKey->v.str, "apv_id") == 0) {
			keyNew = COSE_Header_KDF_V_name;
			pValueNew = cn_cbor_data_create(pValue->v.bytes,
				(int)pValue->length, CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else if (strcmp(pKey->v.str, "pub_other") == 0) {
			keyNew = COSE_Header_KDF_PUB_other;
			pValueNew = cn_cbor_data_create(pValue->v.bytes,
				(int)pValue->length, CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else if (strcmp(pKey->v.str, "priv_other") == 0) {
			keyNew = COSE_Header_KDF_PRIV;
			pValueNew = cn_cbor_data_create(pValue->v.bytes,
				(int)pValue->length, CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else if (strcmp(pKey->v.str, "spk") == 0) {
			keyNew = COSE_Header_ECDH_STATIC;
			pValueNew = BuildCborKey(pValue, fPublicKey);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else if (strcmp(pKey->v.str, "compressed") == 0) {
			keyNew = COSE_Header_UseCompressedECDH;
			pValueNew = cn_cbor_bool_create(pValue->v.sint == 1 ? true : false,
				CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (pValueNew == nullptr) {
				return false;
			}
		}
		else {
			continue;
		}

		switch (msgType) {
#if INCLUDE_MAC
			case Attributes_MAC_protected:
				fRet &= COSE_Mac_map_put_int(
					(HCOSE_MAC)hHandle, keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_MAC0
			case Attributes_MAC0_protected:
				fRet &= COSE_Mac0_map_put_int(
					(HCOSE_MAC0)hHandle, keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
			case Attributes_Recipient_protected:
				fRet &= COSE_Recipient_map_put_int((HCOSE_RECIPIENT)hHandle,
					keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_ENCRYPT
			case Attributes_Enveloped_protected:
				fRet &= COSE_Enveloped_map_put_int((HCOSE_ENVELOPED)hHandle,
					keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_ENCRYPT0
			case Attributes_Encrypt_protected:
				fRet &= COSE_Encrypt_map_put_int(
					(HCOSE_ENCRYPT)hHandle, keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_SIGN
			case Attributes_Sign_protected:
				fRet &= COSE_Sign_map_put_int(
					(HCOSE_SIGN)hHandle, keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_SIGN
			case Attributes_Signer_protected:
				fRet &= COSE_Signer_map_put_int(
					(HCOSE_SIGNER)hHandle, keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_SIGN1
			case Attributes_Sign1_protected:
				fRet &= COSE_Sign1_map_put_int(
					(HCOSE_SIGN1)hHandle, keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_COUNTERSIGNATURE
			case Attributes_Countersign_protected:
				fRet &= COSE_CounterSign_map_put_int((HCOSE_COUNTERSIGN)hHandle,
					keyNew, pValueNew, which, nullptr);
				break;
#endif

#if INCLUDE_COUNTERSIGNATURE1
			case Attributes_Countersign1_protected:
				fRet &=
					COSE_CounterSign1_map_put_int((HCOSE_COUNTERSIGN1)hHandle,
						keyNew, pValueNew, which, nullptr);
				break;
#endif

			default:
				fRet = false;
				assert(false);
				break;
		}

		if (fRet) {
			pValueNew.Clear();
		}
		//  If you uncomment this then the memory test will fail.
		// assert(fRet);
	}

	return fRet;
}

bool SetSendingAttributes(void* pMsg, const cn_cbor* pIn, int base)
{
	bool f = false;
	const HCOSE hMsg = static_cast<HCOSE>(pMsg);

	if (!SetAttributes(hMsg, cn_cbor_mapget_string(pIn, "protected"),
			COSE_PROTECT_ONLY, base, true)) {
		return false;
	}
	if (!SetAttributes(hMsg, cn_cbor_mapget_string(pIn, "unprotected"),
			COSE_UNPROTECT_ONLY, base, true)) {
		return false;
	}
	if (!SetAttributes(hMsg, cn_cbor_mapget_string(pIn, "unsent"),
			COSE_DONT_SEND, base, false)) {
		return false;
	}

	cn_cbor* pExternal = cn_cbor_mapget_string(pIn, "external");
	if (pExternal != nullptr) {
		cn_cbor* pcn = pExternal;
		if (pcn == nullptr) {
			return false;
		}
		switch (base) {
#if INCLUDE_ENCRYPT0
			case Attributes_Encrypt_protected:
				if (!COSE_Encrypt_SetExternal((HCOSE_ENCRYPT)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_ENCRYPT
			case Attributes_Enveloped_protected:
				if (!COSE_Enveloped_SetExternal((HCOSE_ENVELOPED)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_MAC
			case Attributes_MAC_protected:
				if (!COSE_Mac_SetExternal((HCOSE_MAC)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_MAC0
			case Attributes_MAC0_protected:
				if (!COSE_Mac0_SetExternal((HCOSE_MAC0)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_SIGN
			case Attributes_Signer_protected:
				if (!COSE_Signer_SetExternal((HCOSE_SIGNER)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_SIGN1
			case Attributes_Sign1_protected:
				if (!COSE_Sign1_SetExternal((HCOSE_SIGN1)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif
#if INCLUDE_COUNTERSIGNATURE
			case Attributes_Countersign_protected:
				if (!COSE_CounterSign_SetExternal((HCOSE_COUNTERSIGN)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif
			default:
				assert(false);
				break;
		}
	}

	return true;
}

bool SetReceivingAttributes(void* pMsg, const cn_cbor* pIn, int base)
{
	bool f = false;
	HCOSE hMsg = static_cast<HCOSE>(pMsg);

	if (!SetAttributes(hMsg, cn_cbor_mapget_string(pIn, "unsent"),
			COSE_DONT_SEND, base, true)) {
		return false;
	}

	cn_cbor* pExternal = cn_cbor_mapget_string(pIn, "external");
	if (pExternal != nullptr) {
		cn_cbor* pcn = pExternal;
		if (pcn == nullptr) {
			return false;
		}
		switch (base) {
#if INCLUDE_ENCRYPT0
			case Attributes_Encrypt_protected:
				if (!COSE_Encrypt_SetExternal((HCOSE_ENCRYPT)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_ENCRYPT
			case Attributes_Enveloped_protected:
				if (!COSE_Enveloped_SetExternal((HCOSE_ENVELOPED)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_MAC
			case Attributes_MAC_protected:
				if (!COSE_Mac_SetExternal((HCOSE_MAC)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_MAC0
			case Attributes_MAC0_protected:
				if (!COSE_Mac0_SetExternal((HCOSE_MAC0)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_SIGN
			case Attributes_Signer_protected:
				if (!COSE_Signer_SetExternal((HCOSE_SIGNER)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif

#if INCLUDE_SIGN1
			case Attributes_Sign1_protected:
				if (!COSE_Sign1_SetExternal((HCOSE_SIGN1)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif
#if INCLUDE_COUNTERSIGNATURE
			case Attributes_Countersign_protected:
				if (!COSE_CounterSign_SetExternal((HCOSE_COUNTERSIGN)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif
#if INCLUDE_COUNTERSIGNATURE1
			case Attributes_Countersign1_protected:
				if (!COSE_CounterSign1_SetExternal((HCOSE_COUNTERSIGN1)hMsg,
						FromHex(pcn->v.str, (int)pcn->length), pcn->length / 2,
						nullptr)) {
					return false;
				}
				break;
#endif
		}
	}

	return true;
}

cn_cbor* BuildCborKey(const cn_cbor* pKeyIn, bool fPublicKey)
{
	Safe_CN_CBOR pKeyOut = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor* pKty = cn_cbor_mapget_string(pKeyIn, "kty");
	cn_cbor* pKey = nullptr;
	size_t i;
	int kty;
	unsigned char* pb = nullptr;
	size_t cb;

	if (pKeyOut == nullptr) {
		return nullptr;
	}

	if ((pKty == nullptr) || (pKty->type != CN_CBOR_TEXT)) {
		return nullptr;
	}
	if (pKty->length == 2) {
		if (strncmp(pKty->v.str, "EC", 2) == 0) {
			kty = 2;
		}
		else {
			return nullptr;
		}
	}
	else if (pKty->length == 3) {
		if (strncmp(pKty->v.str, "oct", 3) == 0) {
			kty = 4;
		}
		else if (strncmp(pKty->v.str, "OKP", 3) == 0) {
			kty = COSE_Key_Type_OKP;
		}
		else {
			return nullptr;
		}
	}
	else {
		return nullptr;
	}

	Safe_CN_CBOR p = cn_cbor_int_create(kty, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (p == nullptr) {
		return nullptr;
	}
	if (!cn_cbor_mapput_int(pKeyOut, 1, p, CBOR_CONTEXT_PARAM_COMMA nullptr)) {
		return nullptr;
	}
	p.Clear();

	for (pKey = pKeyIn->first_child; pKey != nullptr; pKey = pKey->next->next) {
		cn_cbor* pValue = pKey->next;

		if (pKey->type == CN_CBOR_TEXT) {
			for (i = 0; i < sizeof(RgStringKeys) / sizeof(RgStringKeys[0]);
				 i++) {
				if (((size_t)pKey->length == strlen(RgStringKeys[i].szKey)) &&
					(strncmp(pKey->v.str, RgStringKeys[i].szKey,
						 strlen(RgStringKeys[i].szKey)) == 0) &&
					((RgStringKeys[i].kty == 0) ||
						(RgStringKeys[i].kty == kty))) {
					Safe_CN_CBOR pValueNew;

					switch (RgStringKeys[i].operation) {
						case OPERATION_NONE:
							pValueNew = cn_cbor_clone(
								pValue, CBOR_CONTEXT_PARAM_COMMA nullptr);
							if (pValueNew == nullptr) {
								return nullptr;
							}
							if (!cn_cbor_mapput_int(pKeyOut,
									RgStringKeys[i].keyNew, pValueNew,
									CBOR_CONTEXT_PARAM_COMMA nullptr)) {
								return nullptr;
							}
							break;

						case OPERATION_BASE64:
							if ((strcmp(pKey->v.str, "d") == 0) && fPublicKey) {
								continue;
							}

							pb = base64_decode(
								pValue->v.str, pValue->length, &cb);
							pValueNew = cn_cbor_data_create(
								pb, (int)cb, CBOR_CONTEXT_PARAM_COMMA nullptr);
							if (pValueNew == nullptr) {
								return nullptr;
							}
							if (!cn_cbor_mapput_int(pKeyOut,
									RgStringKeys[i].keyNew, pValueNew,
									CBOR_CONTEXT_PARAM_COMMA nullptr)) {
								return nullptr;
							}
							break;

						case OPERATION_STRING:
							pValueNew =
								cn_cbor_int_create(MapName(pValue, RgCurveNames,
													   _countof(RgCurveNames)),
									CBOR_CONTEXT_PARAM_COMMA nullptr);
							if (pValueNew == nullptr) {
								return nullptr;
							}
							if (!cn_cbor_mapput_int(pKeyOut,
									RgStringKeys[i].keyNew, pValueNew,
									CBOR_CONTEXT_PARAM_COMMA nullptr)) {
								return nullptr;
							}
							break;

						case OPERATION_HEX:
							if ((strcmp(pKey->v.str, "d_hex") == 0) &&
								fPublicKey) {
								continue;
							}
							pb = hex_decode(pValue->v.str, pValue->length, &cb);
							pValueNew = cn_cbor_data_create(
								pb, (int)cb, CBOR_CONTEXT_PARAM_COMMA nullptr);
							if (pValueNew == nullptr) {
								return nullptr;
							}
							if (!cn_cbor_mapput_int(pKeyOut,
									RgStringKeys[i].keyNew, pValueNew,
									CBOR_CONTEXT_PARAM_COMMA nullptr)) {
								return nullptr;
							}
							break;
					}
					pValueNew.Clear();
					i = 99;
				}
			}
		}
	}
	cn_cbor* pOut = pKeyOut;
	pKeyOut.Clear();
	return pOut;
}

HCOSE_KEY BuildKey(const cn_cbor* pKeyIn, bool fPublicKey)
{
	cose_errback coseError;
	cn_cbor* pKeyOut = BuildCborKey(pKeyIn, fPublicKey);
	if (pKeyOut == nullptr) {
		return nullptr;
	}

	Safe_HCOSE_KEY key =
		COSE_KEY_FromCbor(pKeyOut, CBOR_CONTEXT_PARAM_COMMA & coseError);
	if (key == nullptr) {
		CN_CBOR_FREE(pKeyOut, context);
		return nullptr;
	}
	if (KeyFormat == 1) {
		return key.Release();
	}

	cn_cbor* keyType = cn_cbor_mapget_int(pKeyOut, COSE_Key_Type);
	if (keyType == nullptr) {
		return nullptr;
	}

#ifdef COSE_C_USE_OPENSSL
	EVP_PKEY* opensslKey = nullptr;
#endif
#ifdef COSE_C_USE_MBEDTLS
	mbedtls_ecp_keypair* keypair = nullptr;
#endif

	switch (keyType->v.uint) {
		case COSE_Key_Type_EC2:
#if defined(COSE_C_USE_OPENSSL)
		{
			opensslKey = EVP_FromKey((COSE_KEY*)(HCOSE_KEY)key,
				CBOR_CONTEXT_PARAM_COMMA & coseError);
		}
#endif
#ifdef COSE_C_USE_MBEDTLS
			{
				keypair = static_cast<mbedtls_ecp_keypair*>(
					COSE_CALLOC(sizeof(*keypair), 1, context));
				if (keypair == nullptr) {
					return nullptr;
				}
				mbedtls_ecp_keypair_init(keypair);
				if (!ECKey_From(
						(COSE_KEY*)(HCOSE_KEY)key, keypair, &coseError)) {
					mbedtls_ecp_keypair_free(keypair);
					COSE_FREE(keypair, context);
					return nullptr;
				}
			}
#endif
			break;

		case COSE_Key_Type_OKP:
#ifdef COSE_C_USE_OPENSSL
			opensslKey = EVP_FromKey((COSE_KEY*)(HCOSE_KEY)key,
				CBOR_CONTEXT_PARAM_COMMA & coseError);
#endif
			break;

		default:
			break;
	}

#if defined(COSE_C_USE_OPENSSL)

	if (opensslKey == nullptr) {
		return key.Release();
	}
	else {
		HCOSE_KEY key2 =
			COSE_KEY_FromEVP(opensslKey, KeyFormat == 2 ? nullptr : pKeyOut,
				CBOR_CONTEXT_PARAM_COMMA & coseError);
		if (key2 == nullptr) {
			EVP_PKEY_free(opensslKey);
		}
		else if (KeyFormat == 3) {
			// M00BUG - figure out how to get it back.  Might be a dup
			// CN_CBOR_FREE(pKeyOut, context);
		}
		return key2;
	}
#endif
#ifdef COSE_C_USE_MBEDTLS
	if (keypair == nullptr) {
		return key.Release();
	}
	else {
		HCOSE_KEY k2 = COSE_KEY_FromMbedKeypair(keypair,
			KeyFormat == 2 ? nullptr : pKeyOut, COSE_KEY_FL_OWN,
			CBOR_CONTEXT_PARAM_COMMA & coseError);
		if (k2 == nullptr) {
			mbedtls_ecp_keypair_free(keypair);
			COSE_FREE(keypair, context);
		}
		else if (KeyFormat == 3) {
			//  see note above
			// CN_CBOR_FREE(pKeyOut, context);
		}
		return k2;
	}
#endif

	return nullptr;
}

bool Test_cn_cbor_array_replace()
{
	cn_cbor* pRoot;
	cn_cbor* pItem;

	//  Cases that are not currently covered
	//  1.  Pass in invalid arguements

	cn_cbor_array_replace(
		nullptr, nullptr, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);

	//  2.  Insert 0 item with no items currently in the list
	pRoot = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA nullptr);
	pItem = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_array_replace(pRoot, pItem, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);

	//  3. Insert 0 item w/ exactly one item in the list
	pItem = cn_cbor_int_create(6, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_array_replace(pRoot, pItem, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);

	//  4.  The last item in the array
	pItem = cn_cbor_int_create(7, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_array_replace(pRoot, pItem, 1, CBOR_CONTEXT_PARAM_COMMA nullptr);

	pItem = cn_cbor_int_create(8, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_array_replace(pRoot, pItem, 1, CBOR_CONTEXT_PARAM_COMMA nullptr);

	return true;
}

bool AreListsEmpty();

void RunCorners()
{
	Test_cn_cbor_array_replace();
#if INCLUDE_MAC
	MAC_Corners();
#endif
#if INCLUDE_MAC0
	MAC0_Corners();
#endif
#if INCLUDE_ENCRYPT0
	Encrypt_Corners();
#endif
#if INCLUDE_ENCRYPT
	Enveloped_Corners();
#endif
#if INCLUDE_SIGN
	Sign_Corners();
#endif
#if INCLUDE_SIGN1
	Sign1_Corners();
#endif
#if INCLUDE_ENCRYPT || INCLUDE_MAC
	Recipient_Corners();
#endif
#if INCLUDE_COUNTERSIGNATURE
	CounterSign_Corners();
#endif
}

static void RunMemoryTest(const char* szFileName)
{
#ifdef USE_CBOR_CONTEXT
	int iFail;
	const cn_cbor* pControl = ParseJson(szFileName);

	if (pControl == NULL) {
		CFails += 1;
		return;
	}

	//
	//  To find out what we are doing we need to get the correct item

	const cn_cbor* pInput = cn_cbor_mapget_string(pControl, "input");

	if ((pInput == NULL) || (pInput->type != CN_CBOR_MAP)) {
		fprintf(stderr, "No or bad input section");
		exit(1);
	}

	//
	bool fValidateDone = false;
	bool fBuildDone = false;

	for (iFail = 0; (!fValidateDone || !fBuildDone) && (iFail < 100000);
		 iFail++) {
		if (cn_cbor_mapget_string(pInput, "mac") != NULL) {
#if INCLUDE_MAC
			if (!fValidateDone) {
				context = CreateContext(iFail);
				CFails = 0;
				ValidateMAC(pControl);
				if (CFails == 0) {
					fValidateDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}

			if (!fBuildDone) {
				context = CreateContext(iFail);
				CFails = 0;
				BuildMacMessage(pControl);
				if (CFails == 0) {
					fBuildDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}
#else
			fValidateDone = true;
			fBuildDone = true;
#endif
		}
		else if (cn_cbor_mapget_string(pInput, "mac0") != NULL) {
#if INCLUDE_MAC0
			if (!fValidateDone) {
				context = CreateContext(iFail);
				CFails = 0;
				ValidateMac0(pControl);
				if (CFails == 0) {
					fValidateDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}

			if (!fBuildDone) {
				context = CreateContext(iFail);
				CFails = 0;
				BuildMac0Message(pControl);
				if (CFails == 0) {
					fBuildDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}
#else
			fValidateDone = true;
			fBuildDone = true;
#endif
		}
		else if (cn_cbor_mapget_string(pInput, "encrypted") != NULL) {
#if INCLUDE_ENCRYPT0
			if (!fValidateDone) {
				context = CreateContext(iFail);
				CFails = 0;
				ValidateEncrypt(pControl);
				if (CFails == 0) {
					fValidateDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}

			if (!fBuildDone) {
				context = CreateContext(iFail);
				CFails = 0;
				BuildEncryptMessage(pControl);
				if (CFails == 0) {
					fBuildDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}
#else
			fValidateDone = true;
			fBuildDone = true;
#endif
		}
		else if (cn_cbor_mapget_string(pInput, "enveloped") != NULL) {
#if INCLUDE_ENCRYPT
			if (!fValidateDone) {
				context = CreateContext(iFail);
				CFails = 0;
				ValidateEnveloped(pControl);
				if (CFails == 0) {
					fValidateDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}

			if (!fBuildDone) {
				context = CreateContext(iFail);
				CFails = 0;
				BuildEnvelopedMessage(pControl);
				if (CFails == 0) {
					fBuildDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}
#else
			fValidateDone = true;
			fBuildDone = true;
#endif
		}
		else if (cn_cbor_mapget_string(pInput, "sign") != NULL) {
#if INCLUDE_SIGN
			if (!fValidateDone) {
				context = CreateContext(iFail);
				CFails = 0;
				ValidateSigned(pControl);
				if (CFails == 0) {
					fValidateDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}

			if (!fBuildDone) {
				context = CreateContext(iFail);
				CFails = 0;
				BuildSignedMessage(pControl);
				if (CFails == 0) {
					fBuildDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}
#else
			fValidateDone = true;
			fBuildDone = true;
#endif
		}
		else if (cn_cbor_mapget_string(pInput, "sign0") != NULL) {
#if INCLUDE_SIGN1
			if (!fValidateDone) {
				context = CreateContext(iFail);
				CFails = 0;
				ValidateSign1(pControl);
				if (CFails == 0) {
					fValidateDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}

			if (!fBuildDone) {
				context = CreateContext(iFail);
				CFails = 0;
				BuildSign1Message(pControl);
				if (CFails == 0) {
					fBuildDone = true;
				}
				if (IsContextEmpty(context) != 0) {
					CFails += 1;
				}
#ifndef NDEBUG
				if (!AreListsEmpty()) {
					CFails += 1;
					break;
				}
#endif
				FreeContext(context);
			}
#else
			fValidateDone = true;
			fBuildDone = true;
#endif
		}
		CFails = 0;
	}
	context = NULL;
#else
	return;
#endif
}

typedef bool (*ValidatePtr)(const cn_cbor* pControl);

bool ProcessFile(const cn_cbor* pControl,
	ValidatePtr validateFunction,
	ValidatePtr buildFunction)
{
#ifdef USE_CBOR_CONTEXT
	context = CreateContext(-1);
#endif
	if (validateFunction(pControl)) {
#ifdef USE_CBOR_CONTEXT
		if (IsContextEmpty(context) != 0) {
			printf("Memory Cleanup Failure - Validate\n");
			// CFails += 1;
		}
#endif
#ifndef NDEBUG
		if (!AreListsEmpty()) {
			printf("Left over handle - P1\n");
			CFails += 1;
		}
#endif
#ifdef USE_CBOR_CONTEXT
		FreeContext(context);
		context = CreateContext(-1);
#endif
		buildFunction(pControl);
#ifdef USE_CBOR_CONTEXT
		if (IsContextEmpty(context) != 0) {
			printf("Memory Cleanup Failure - Build\n");
			// CFails += 1;
		}
#endif
	}
#ifndef NDEBUG
	if (!AreListsEmpty()) {
		printf("Left over handle - P2\n");
		CFails += 1;
	}
#endif
#ifdef USE_CBOR_CONTEXT
	FreeContext(context);
	context = NULL;
#endif
	return true;
}

static void RunFileTest(const char* szFileName)
{
	const cn_cbor* pControl = ParseJson(szFileName);

	//
	//  If we are given a file name, then process the file name
	//

	if (pControl == nullptr) {
		CFails += 1;
		return;
	}

	//  To find out what we are doing we need to get the correct item

	const cn_cbor* pInput = cn_cbor_mapget_string(pControl, "input");

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		fprintf(stderr, "No or bad input section");
		exit(1);
	}

	if (cn_cbor_mapget_string(pInput, "mac") != nullptr) {
#if INCLUDE_MAC
		ProcessFile(pControl, ValidateMAC, BuildMacMessage);
#endif
	}
	else if (cn_cbor_mapget_string(pInput, "mac0") != nullptr) {
#if INCLUDE_MAC0
		ProcessFile(pControl, ValidateMac0, BuildMac0Message);
#endif
	}
	else if (cn_cbor_mapget_string(pInput, "enveloped") != nullptr) {
#if INCLUDE_ENCRYPT
		ProcessFile(pControl, ValidateEnveloped, BuildEnvelopedMessage);
#endif
	}
	else if (cn_cbor_mapget_string(pInput, "sign") != nullptr) {
#if INCLUDE_SIGN
		ProcessFile(pControl, ValidateSigned, BuildSignedMessage);
#endif
	}
	else if (cn_cbor_mapget_string(pInput, "sign0") != nullptr) {
#if INCLUDE_SIGN1
		ProcessFile(pControl, ValidateSign1, BuildSign1Message);
#endif
	}
	else if (cn_cbor_mapget_string(pInput, "encrypted") != nullptr) {
#if INCLUDE_ENCRYPT0
		ProcessFile(pControl, ValidateEncrypt, BuildEncryptMessage);
#endif
	}
}

#ifdef _MSC_VER
void RunTestsInDirectory(const char* szDir)
{
	int cFailTotal = 0;
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	char rgchFullName[2 * 1024];

	if (strlen(szDir) + 7 >= sizeof(rgchFullName)) {
		fprintf(stderr, "Buffer overflow error\n");
		exit(1);
	}
	strcpy(rgchFullName, szDir);
	strcat(rgchFullName, "\\");
	size_t ich = strlen(rgchFullName);
	strcat(rgchFullName, "*.json");

	hFind = FindFirstFile(rgchFullName, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("FindFirstFile failed (%d)\n", GetLastError());
		return;
	}

	do {
		rgchFullName[ich] = 0;
		if (ich + strlen(FindFileData.cFileName) >= sizeof(rgchFullName)) {
			fprintf(stderr, "Buffer overflow problem\n");
			exit(1);
		}
		strcat(rgchFullName, FindFileData.cFileName);
		printf("Run test '%s'", rgchFullName);

		CFails = 0;
		RunFileTest(rgchFullName);
		if (CFails == 0) {
			printf(" PASS\n");
		}
		else {
			printf(" FAILED\n");
		}
		cFailTotal += CFails;
	} while (FindNextFile(hFind, &FindFileData));

	FindClose(hFind);

	CFails = cFailTotal;
}

#else
void RunTestsInDirectory(const char* szDir)
{
	DIR* dirp = opendir(szDir);
	struct dirent* dp;
	char rgchFullName[2 * 1024];
	int ich;
	int cFailTotal = 0;

	if (dirp == NULL) {
		fprintf(stderr, "Cannot open directory '%s'\n", szDir);
		exit(1);
	}
	if (strlen(szDir) >= sizeof(rgchFullName) - 3) {
		fprintf(stderr, "Buffer overflow problem\n");
		exit(1);
	}
	strcpy(rgchFullName, szDir);
	strcat(rgchFullName, "/");
	ich = strlen(rgchFullName);

	while ((dp = readdir(dirp)) != NULL) {
		int cch = strlen(dp->d_name);
		if (cch < 4)
			continue;
		rgchFullName[ich] = 0;
		if (ich + strlen(dp->d_name) >= sizeof(rgchFullName) - 2) {
			fprintf(stderr, "Buffer overflow problem\n");
			exit(1);
		}
		strcat(rgchFullName, dp->d_name);
		printf("Run test '%s'", rgchFullName);
		CFails = 0;
		RunFileTest(rgchFullName);
		if (CFails == 0)
			printf(" PASS\n");
		else
			printf(" FAILED\n");
		cFailTotal += CFails;
	}

	(void)closedir(dirp);
	exit(cFailTotal);
}
#endif	// _MSCVER

int main(int argc, char** argv)
{
	int i;
	const char* szWhere = nullptr;
	bool fDir = false;
	bool fCorners = false;
	bool fMemory = false;

	for (i = 1; i < argc; i++) {
		printf("arg: '%s'\n", argv[i]);
		if (argv[i][0] == '-') {
			if (strcmp(argv[i], "--dir") == 0) {
				fDir = true;
			}
			else if (strcmp(argv[i], "--corners") == 0) {
				fCorners = true;
			}
			else if (strcmp(argv[i], "--memory") == 0) {
				fMemory = true;
			}
			else if (strcmp(argv[i], "--keyFormat=native") == 0) {
				KeyFormat = 2;
#if defined(COSE_C_USE_OPENSSL) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
#pragma message("OPENSSL VERSION does not support native key ")

				fprintf(stderr,
					"Native key formats not supported for OpenSSL version "
					"{%x}\n",
					OPENSSL_VERSION_NUMBER);
				exit(0);
#endif
			}
			else if (strcmp(argv[i], "--keyFormat=both") == 0) {
				KeyFormat = 3;
			}
		}
		else {
			szWhere = argv[i];
		}
	}

#ifdef COSE_C_USE_MBEDTLS
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
#endif

	//
	//  If we are given a file name, then process the file name
	//

	if (fMemory) {
		if (szWhere == nullptr) {
			fprintf(stderr, "Must specify a file name\n");
			exit(1);
		}
		RunMemoryTest(szWhere);
	}
	else if (szWhere != nullptr) {
		if (szWhere == nullptr) {
			fprintf(stderr, "Must specify a file name\n");
			exit(1);
		}
		if (fDir) {
			RunTestsInDirectory(szWhere);
		}
		else {
			RunFileTest(szWhere);
		}
	}
	else if (fCorners) {
#ifdef USE_CBOR_CONTEXT
		context = CreateContext(-1);
#endif
		RunCorners();
#ifdef USE_CBOR_CONTEXT
		FreeContext(context);
#endif
	}
	else {
#ifdef USE_CBOR_CONTEXT
		context = CreateContext(-1);
#endif
#if INCLUDE_MAC
		MacMessage();
#endif
#if INCLUDE_SIGN
		SignMessage();
#endif
#if INCLUDE_ENCRYPT
		EncryptMessage();
#endif
#ifdef USE_CBOR_CONTEXT
		FreeContext(context);
#endif
	}

	if (CFails > 0) {
		fprintf(stderr, "Failed %d tests\n", CFails);
	}
	else {
		fprintf(stderr, "SUCCESS\n");
	}

	exit(CFails);
}
