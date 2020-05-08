//  encrypt.c

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose/cose.h>
#include <cose/cose_configure.h>
#include <cn-cbor/cn-cbor.h>
#if (INCLUDE_SIGN && !(INCLUDE_SIGN1 || INCLUDE_ENCRYPT || INCLUDE_MAC)) || \
	(INCLUDE_SIGN1 && !INCLUDE_SIGN)
#include <cose_int.h>
#endif

#include "json.h"
#include "test.h"
#include "context.h"
#include "cose_int.h"

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

#if INCLUDE_SIGN
int _ValidateSigned(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor *pFail;
	const cn_cbor *pSign;
	const cn_cbor *pSigners;
	HCOSE_SIGN hSig = nullptr;
	HCOSE_SIGNER hSigner = nullptr;
	int type;
	int iSigner;
	bool fFail = false;
	bool fFailBody = false;
	bool fNoSupportAlg = false;
	HCOSE_COUNTERSIGN h = nullptr;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		goto returnError;
	}
	pSign = cn_cbor_mapget_string(pInput, "sign");
	if ((pSign == nullptr) || (pSign->type != CN_CBOR_MAP)) {
		goto returnError;
	}

	pSigners = cn_cbor_mapget_string(pSign, "signers");
	if ((pSigners == nullptr) || (pSigners->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	iSigner = (int)pSigners->length - 1;
	pSigners = pSigners->first_child;
	for (; pSigners != nullptr; iSigner--, pSigners = pSigners->next) {
		hSig = (HCOSE_SIGN)COSE_Decode(pbEncoded, cbEncoded, &type,
			COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hSig == nullptr) {
			if (fFailBody) {
				return 0;
			}
			else {
				goto returnError;
			}
		}
		if (!SetReceivingAttributes(
				(HCOSE)hSig, pSign, Attributes_Sign_protected)) {
			goto returnError;
		}

		cn_cbor *pkey = BuildKey(cn_cbor_mapget_string(pSigners, "key"), false);
		if (pkey == nullptr) {
			goto returnError;
		}

		HCOSE_SIGNER hSigner = COSE_Sign_GetSigner(hSig, iSigner, nullptr);
		if (hSigner == nullptr) {
			goto returnError;
		}
		if (!SetReceivingAttributes(
				(HCOSE)hSigner, pSigners, Attributes_Signer_protected)) {
			goto returnError;
		}

		if (!COSE_Signer_SetKey(hSigner, pkey, nullptr)) {
			goto returnError;
		}

		cn_cbor *alg = COSE_Signer_map_get_int(
			hSigner, COSE_Header_Algorithm, COSE_BOTH, 0);
		if (!IsAlgorithmSupported(alg)) {
			fNoSupportAlg = true;
		}

		pFail = cn_cbor_mapget_string(pSigners, "fail");
		if (COSE_Sign_validate(hSig, hSigner, nullptr)) {
			if (fNoSupportAlg) {
				fFail = true;
			}
			else if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
				fFail = true;
			}
		}
		else {
			if (fNoSupportAlg) {
				fFailBody = false;
				fFail = false;
			}
			else if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
				fFail = true;
			}
		}

#if INCLUDE_COUNTERSIGNATURE
		//  Validate counter signatures on signers
		cn_cbor *countersignList =
			cn_cbor_mapget_string(pSigners, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				fFail = true;
				continue;
			}
			size_t count = countersigners->length;
			bool forward = true;

			if (COSE_Signer_map_get_int(hSigner, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, 0) == nullptr) {
				goto returnError;
			}

			for (size_t counterNo = 0; counterNo < count; counterNo++) {
				bool noSignAlg = false;

				h = COSE_Signer_get_countersignature(hSigner, counterNo, 0);
				if (h == nullptr) {
					fFail = true;
					continue;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners,
					forward ? counterNo : count - counterNo - 1);

				cn_cbor *pkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (pkeyCountersign == nullptr) {
					fFail = true;
					COSE_CounterSign_Free(h);
					continue;
				}

				if (!COSE_CounterSign_SetKey(h, pkeyCountersign, 0)) {
					fFail = true;
					COSE_CounterSign_Free(h);
					CN_CBOR_FREE(pkeyCountersign, context);
					continue;
				}

				alg = COSE_CounterSign_map_get_int(
					h, COSE_Header_Algorithm, COSE_BOTH, 0);
				if (!IsAlgorithmSupported(alg)) {
					fNoSupportAlg = true;
					noSignAlg = true;
				}

				if (COSE_Signer_CounterSign_validate(hSigner, h, 0)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
					}
					else {
						fFail |= !noSignAlg;
					}
				}

				COSE_CounterSign_Free(h);
			}
		}
#endif

#if INCLUDE_COUNTERSIGNATURE
		//  Countersign on Signed Body

		if (iSigner == 0) {
			//  Validate counter signatures on signers
			countersignList = cn_cbor_mapget_string(pSign, "countersign");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					fFail = true;
					continue;
				}
				int count = countersigners->length;
				bool forward = true;

				if (COSE_Sign_map_get_int(hSig, COSE_Header_CounterSign,
						COSE_UNPROTECT_ONLY, 0) == nullptr) {
					goto returnError;
				}

				for (int counterNo = 0; counterNo < count; counterNo++) {
					bool noSignAlg = false;

					HCOSE_COUNTERSIGN h =
						COSE_Sign_get_countersignature(hSig, counterNo, 0);
					if (h == nullptr) {
						fFail = true;
						continue;
					}

					cn_cbor *counterSigner = cn_cbor_index(countersigners,
						forward ? counterNo : count - counterNo - 1);

					cn_cbor *pkeyCountersign = BuildKey(
						cn_cbor_mapget_string(counterSigner, "key"), false);
					if (pkeyCountersign == nullptr) {
						fFail = true;
						COSE_CounterSign_Free(h);
						continue;
					}

					if (!COSE_CounterSign_SetKey(h, pkeyCountersign, 0)) {
						fFail = true;
						COSE_CounterSign_Free(h);
						CN_CBOR_FREE(pkeyCountersign, context);
						continue;
					}

					alg = COSE_CounterSign_map_get_int(
						h, COSE_Header_Algorithm, COSE_BOTH, 0);
					if (!IsAlgorithmSupported(alg)) {
						fNoSupportAlg = true;
						noSignAlg = true;
					}

					if (COSE_Sign_CounterSign_validate(hSig, h, 0)) {
						//  I don't think we have any forced errors yet.
					}
					else {
						if (forward && counterNo == 0 && count > 1) {
							forward = false;
							counterNo -= 1;
						}
						else {
							fFail |= !noSignAlg;
						}
					}

					COSE_CounterSign_Free(h);
				}
			}
		}
#endif

		COSE_Sign_Free(hSig);
		COSE_Signer_Free(hSigner);
	}

	if (fFailBody) {
		if (!fFail) {
			fFail = true;
		}
		else {
			fFail = false;
		}
	}

	if (fFail) {
		CFails += 1;
	}
	return fNoSupportAlg ? 0 : 1;

returnError:
	if (hSigner != nullptr) {
		COSE_Signer_Free(hSigner);
	}
	if (hSig != nullptr) {
		COSE_Sign_Free(hSig);
	}

	CFails += 1;
	return 0;
}

int ValidateSigned(const cn_cbor *pControl)
{
	int cbEncoded;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateSigned(pControl, pbEncoded, cbEncoded);
}

int BuildSignedMessage(const cn_cbor *pControl)
{
	int iSigner;
	HCOSE_SIGNER hSigner = nullptr;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return 0;
	}

	HCOSE_SIGN hSignObj =
		COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		if (hSignObj != nullptr) {
			COSE_Sign_Free(hSignObj);
		}
		if (hSigner != nullptr) {
			COSE_Signer_Free(hSigner);
		}

		CFails += 1;
		return 1;
	}
	const cn_cbor *pSign = cn_cbor_mapget_string(pInputs, "sign");
	if (pSign == nullptr) {
		goto returnError;
	}

	const cn_cbor *pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Sign_SetContent(
			hSignObj, pContent->v.bytes, pContent->length, nullptr)) {
		goto returnError;
	}

	if (!SetSendingAttributes(
			(HCOSE)hSignObj, pSign, Attributes_Sign_protected)) {
		goto returnError;
	}

	const cn_cbor *pSigners = cn_cbor_mapget_string(pSign, "signers");
	if ((pSigners == nullptr) || (pSigners->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pSigners = pSigners->first_child;
	for (iSigner = 0; pSigners != nullptr; iSigner++, pSigners = pSigners->next) {
		cn_cbor *pkey = BuildKey(cn_cbor_mapget_string(pSigners, "key"), false);
		if (pkey == nullptr) {
			goto returnError;
		}

		hSigner = COSE_Signer_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hSigner == nullptr) {
			goto returnError;
		}

		if (!SetSendingAttributes(
				(HCOSE)hSigner, pSigners, Attributes_Signer_protected)) {
			goto returnError;
		}

		if (!COSE_Signer_SetKey(hSigner, pkey, nullptr)) {
			goto returnError;
		}

		if (!COSE_Sign_AddSigner(hSignObj, hSigner, nullptr)) {
			goto returnError;
		}

#if INCLUDE_COUNTERSIGNATURE
		//  On the signer object
		cn_cbor *countersigns = cn_cbor_mapget_string(pSigners, "countersign");
		if (countersigns != nullptr) {
			countersigns = cn_cbor_mapget_string(countersigns, "signers");
			cn_cbor *countersign = countersigns->first_child;

			for (; countersign != nullptr; countersign = countersign->next) {
				cn_cbor *pkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (pkeyCountersign == nullptr) {
					goto returnError;
				}

				HCOSE_COUNTERSIGN hCountersign =
					COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
				if (hCountersign == nullptr) {
					goto returnError;
				}

				if (!SetSendingAttributes((HCOSE)hCountersign, countersign,
						Attributes_Countersign_protected)) {
					COSE_CounterSign_Free(hCountersign);
					goto returnError;
				}

				if (!COSE_CounterSign_SetKey(
						hCountersign, pkeyCountersign, nullptr)) {
					COSE_CounterSign_Free(hCountersign);
					goto returnError;
				}

				if (!COSE_Signer_add_countersignature(
						hSigner, hCountersign, nullptr)) {
					COSE_CounterSign_Free(hCountersign);
					goto returnError;
				}

				COSE_CounterSign_Free(hCountersign);
			}
		}
#endif
		COSE_Signer_Free(hSigner);
	}
#if INCLUDE_COUNTERSIGNATURE
	// On the sign body
	cn_cbor *countersigns1 = cn_cbor_mapget_string(pSign, "countersign");
	if (countersigns1 != nullptr) {
		countersigns1 = cn_cbor_mapget_string(countersigns1, "signers");
		cn_cbor *countersign = countersigns1->first_child;

		for (; countersign != nullptr; countersign = countersign->next) {
			cn_cbor *pkeyCountersign =
				BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
			if (pkeyCountersign == nullptr) {
				goto returnError;
			}

			HCOSE_COUNTERSIGN hCountersign =
				COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (hCountersign == nullptr) {
				goto returnError;
			}

			if (!SetSendingAttributes((HCOSE)hCountersign, countersign,
					Attributes_Countersign_protected)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			if (!COSE_CounterSign_SetKey(hCountersign, pkeyCountersign, nullptr)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			if (!COSE_Sign_add_countersignature(hSignObj, hCountersign, nullptr)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			COSE_CounterSign_Free(hCountersign);
		}
	}

#endif

	if (!COSE_Sign_Sign(hSignObj, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode((HCOSE)hSignObj, nullptr, 0, 0) + 1;
	byte *rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hSignObj, rgb, 0, cb);

	COSE_Sign_Free(hSignObj);

	int f = _ValidateSigned(pControl, rgb, cb);

	free(rgb);
	return f;
}

int SignMessage()
{
	HCOSE_SIGN hEncObj =
		COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	char *sz = "This is the content to be used";
	size_t cb;
	byte *rgb;

	byte rgbX[] = {0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba, 0xe8, 0x29,
		0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a, 0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb,
		0x5b, 0x5d, 0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d};
	byte rgbY[] = {0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7, 0xf9, 0xe4,
		0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d, 0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0,
		0xca, 0x7c, 0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c};
	byte kid[] = {0x6d, 0x65, 0x72, 0x69, 0x61, 0x64, 0x6f, 0x63, 0x2e, 0x62,
		0x72, 0x61, 0x6e, 0x64, 0x79, 0x62, 0x75, 0x63, 0x6, 0xb4, 0x06, 0x27,
		0x56, 0x36, 0xb6, 0xc6, 0x16, 0xe6, 0x42, 0xe6, 0x57, 0x86, 0x16, 0xd7,
		0x06, 0x65};
	byte rgbD[] = {0xaf, 0xf9, 0x07, 0xc9, 0x9f, 0x9a, 0xd3, 0xaa, 0xe6, 0xc4,
		0xcd, 0xf2, 0x11, 0x22, 0xbc, 0xe2, 0xbd, 0x68, 0xb5, 0x28, 0x3e, 0x69,
		0x07, 0x15, 0x4a, 0xd9, 0x11, 0x84, 0x0f, 0xa2, 0x08, 0xcf};

	cn_cbor *pkey = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, COSE_Key_Type,
		cn_cbor_int_create(COSE_Key_Type_EC2, CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, -1,
		cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, -2,
		cn_cbor_data_create(rgbX, sizeof(rgbX), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, -3,
		cn_cbor_data_create(rgbY, sizeof(rgbY), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, COSE_Key_ID,
		cn_cbor_data_create(kid, sizeof(kid), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, -4,
		cn_cbor_data_create(rgbD, sizeof(rgbD), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);

	COSE_Sign_SetContent(hEncObj, (byte *)sz, strlen(sz), nullptr);
	COSE_Signer_Free(COSE_Sign_add_signer(
		hEncObj, pkey, COSE_Algorithm_ECDSA_SHA_256, nullptr));

	COSE_Sign_Sign(hEncObj, nullptr);

	cb = COSE_Encode((HCOSE)hEncObj, nullptr, 0, 0) + 1;
	rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);

	COSE_Sign_Free(hEncObj);

	FILE *fp = fopen("test.mac.cbor", "wb");
	fwrite(rgb, cb, 1, fp);
	fclose(fp);

#if 0
	char * szX;
	int cbPrint = 0;
	cn_cbor * cbor = COSE_get_cbor((HCOSE)hEncObj);
	cbPrint = cn_cbor_printer_write(nullptr, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, "%s", szX);
	fprintf(stdout, "\r\n");
#endif

	/* */

	int typ;
	hEncObj = (HCOSE_SIGN)COSE_Decode(
		rgb, (int)cb, &typ, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA nullptr);

#if 0
	int iSigner = 0;
	do {
		HCOSE_RECIPIENT hSigner;

		hSigner = COSE_Encrypt_GetRecipient(hEncObj, iSigner, nullptr);
		if (hSigner == nullptr) break;

		COSE_Recipient_SetKey(hSigner, rgbSecret, cbSecret, nullptr);

		COSE_Encrypt_decrypt(hEncObj, hSigner, nullptr);

		iSigner += 1;

	} while (true);
#endif

	COSE_Sign_Free(hEncObj);

	return 1;
}
#endif

#if INCLUDE_SIGN1
int _ValidateSign1(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor *pFail;
	const cn_cbor *pSign;
	HCOSE_SIGN1 hSig = nullptr;
	cn_cbor *pkey = nullptr;
	int type;
	bool fFail = false;
	bool fFailBody = false;
	bool fNoAlgSupport = false;

	if (false) {
	exitHere:
		if (hSig != nullptr) {
			COSE_Sign1_Free(hSig);
		}

		if (fFail) {
			CFails += 1;
		}
		if (pkey != nullptr) {
			CN_CBOR_FREE(pkey, context);
		}
		return fNoAlgSupport ? 0 : 1;

	returnError:
		if (hSig != nullptr) {
			COSE_Sign1_Free(hSig);
		}

		CFails += 1;
		return 0;		
	}

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		goto returnError;
	}
	pSign = cn_cbor_mapget_string(pInput, "sign0");
	if ((pSign == nullptr) || (pSign->type != CN_CBOR_MAP)) {
		goto returnError;
	}

	hSig = (HCOSE_SIGN1)COSE_Decode(pbEncoded, cbEncoded, &type,
		COSE_sign1_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSig == nullptr) {
		if (fFailBody) {
			return 0;
		}
		else {
			goto returnError;
		}
	}

	if (!SetReceivingAttributes(
			(HCOSE)hSig, pSign, Attributes_Sign1_protected)) {
		goto returnError;
	}

	pkey = BuildKey(cn_cbor_mapget_string(pSign, "key"), false);
	if (pkey == nullptr) {
		fFail = true;
		goto exitHere;
	}

	cn_cbor *alg =
		COSE_Sign1_map_get_int(hSig, COSE_Header_Algorithm, COSE_BOTH, nullptr);
	if (!IsAlgorithmSupported(alg)) {
		fNoAlgSupport = true;
	}

	pFail = cn_cbor_mapget_string(pInput, "fail");
	if (COSE_Sign1_validate(hSig, pkey, nullptr)) {
		if (fNoAlgSupport) {
			fFail = true;
		}
		else if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
			fFail = true;
		}
	}
	else {
		if (fNoAlgSupport) {
			fFailBody = false;
			fFail = false;
		}
		else if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
			fFail = true;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	//  Countersign on Signed Body

	//  Validate counter signatures on signers
	cn_cbor *countersignList = cn_cbor_mapget_string(pSign, "countersign");
	if (countersignList != nullptr) {
		cn_cbor *countersigners =
			cn_cbor_mapget_string(countersignList, "signers");
		if (countersigners == nullptr) {
			fFail = true;
			goto exitHere;
		}
		size_t count = countersigners->length;
		bool forward = true;

		if (COSE_Sign1_map_get_int(hSig, COSE_Header_CounterSign,
				COSE_UNPROTECT_ONLY, 0) == nullptr) {
			goto returnError;
		}

		for (size_t counterNo = 0; counterNo < count; counterNo++) {
			bool noSignAlg = false;

			HCOSE_COUNTERSIGN h =
				COSE_Sign1_get_countersignature(hSig, counterNo, 0);
			if (h == nullptr) {
				fFail = true;
				continue;
			}

			cn_cbor *counterSigner = cn_cbor_index(
				countersigners, forward ? counterNo : count - counterNo - 1);

			cn_cbor *pkeyCountersign =
				BuildKey(cn_cbor_mapget_string(counterSigner, "key"), false);
			if (pkeyCountersign == nullptr) {
				fFail = true;
				COSE_CounterSign_Free(h);
				continue;
			}

			if (!COSE_CounterSign_SetKey(h, pkeyCountersign, 0)) {
				fFail = true;
				COSE_CounterSign_Free(h);
				CN_CBOR_FREE(pkeyCountersign, context);
				continue;
			}

			alg = COSE_Sign1_map_get_int(
				hSig, COSE_Header_Algorithm, COSE_BOTH, nullptr);
			if (!IsAlgorithmSupported(alg)) {
				fNoAlgSupport = true;
				noSignAlg = true;
			}

			if (COSE_Sign1_CounterSign_validate(hSig, h, 0)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (forward && counterNo == 0 && count > 1) {
					forward = false;
					counterNo -= 1;
				}
				else {
					fFail |= !noSignAlg;
				}
			}

			COSE_CounterSign_Free(h);
		}
	}
#endif

	if (fFailBody) {
		if (!fFail) {
			fFail = true;
		}
		else {
			fFail = false;
		}
	}
	goto exitHere;
}

int ValidateSign1(const cn_cbor *pControl)
{
	int cbEncoded = 0;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateSign1(pControl, pbEncoded, cbEncoded);
}

int BuildSign1Message(const cn_cbor *pControl)
{
	cn_cbor *pkey = nullptr;	
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return 0;
	}

	HCOSE_SIGN1 hSignObj =
		COSE_Sign1_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		if (hSignObj != nullptr) {
			COSE_Sign1_Free(hSignObj);
		}
		if (pkey != nullptr) {
			CN_CBOR_FREE(pkey, context);
		}
		CFails += 1;
		return 1;
	}
	const cn_cbor *pSign = cn_cbor_mapget_string(pInputs, "sign0");
	if (pSign == nullptr) {
		goto returnError;
	}

	const cn_cbor *pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Sign1_SetContent(
			hSignObj, pContent->v.bytes, pContent->length, nullptr)) {
		goto returnError;
	}

	if (!SetSendingAttributes(
			(HCOSE)hSignObj, pSign, Attributes_Sign1_protected)) {
		goto returnError;
	}

	pkey = BuildKey(cn_cbor_mapget_string(pSign, "key"), false);
	if (pkey == nullptr) {
		goto returnError;
	}

#if INCLUDE_COUNTERSIGNATURE
	// On the sign body
	cn_cbor *countersigns = cn_cbor_mapget_string(pSign, "countersign");
	if (countersigns != nullptr) {
		countersigns = cn_cbor_mapget_string(countersigns, "signers");
		cn_cbor *countersign = countersigns->first_child;

		for (; countersign != nullptr; countersign = countersign->next) {
			cn_cbor *pkeyCountersign =
				BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
			if (pkeyCountersign == nullptr) {
				goto returnError;
			}

			HCOSE_COUNTERSIGN hCountersign =
				COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (hCountersign == nullptr) {
				goto returnError;
			}

			if (!SetSendingAttributes((HCOSE)hCountersign, countersign,
					Attributes_Countersign_protected)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			if (!COSE_CounterSign_SetKey(hCountersign, pkeyCountersign, nullptr)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			if (!COSE_Sign1_add_countersignature(
					hSignObj, hCountersign, nullptr)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			COSE_CounterSign_Free(hCountersign);
		}
	}

#endif

	if (!COSE_Sign1_Sign(hSignObj, pkey, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode((HCOSE)hSignObj, nullptr, 0, 0) + 1;
	byte *rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hSignObj, rgb, 0, cb);

	COSE_Sign1_Free(hSignObj);
	if (pkey != nullptr) {
		CN_CBOR_FREE(pkey, context);
	}

	int f = _ValidateSign1(pControl, rgb, cb);

	free(rgb);
	return f;
}
#endif

#if INCLUDE_SIGN
void Sign_Corners()
{
	HCOSE_SIGN hSign = nullptr;
	HCOSE_SIGN hSignBad;
	HCOSE_SIGN hSignNULL = nullptr;
	HCOSE_SIGNER hSigner = nullptr;
	HCOSE_SIGNER hSignerBad;
	HCOSE_SIGNER hSignerNULL = nullptr;
	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cose_errback cose_error;

	hSign = COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#if INCLUDE_SIGN1
	hSignBad = (HCOSE_SIGN)COSE_Sign1_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hSignBad = (HCOSE_SIGN)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	hSigner = COSE_Signer_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
#if INCLUDE_ENCRYPT || INCLUDE_MAC
	hSignerBad = (HCOSE_SIGNER)COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hSignerBad = (HCOSE_SIGNER)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	//  Missing case - addref then release on item
	//  Incorrect algorithm

	//  bad handle checks
	//      null handle
	//      wrong type of handle
	//  Null handle checks

	CHECK_FAILURE(
		COSE_Sign_SetContent(hSignNULL, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_SetContent(hSignBad, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_SetContent(hSign, nullptr, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign_map_get_int(hSignNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_map_get_int(hSignBad, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_map_get_int(hSign, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(
		COSE_Sign_map_put_int(hSignNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Sign_map_put_int(hSignBad, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Sign_map_put_int(hSign, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Sign_map_put_int(hSign, 1, cn,
					  COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign_AddSigner(hSignNULL, hSigner, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_AddSigner(hSignBad, hSigner, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_AddSigner(hSign, hSignerNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_AddSigner(hSign, hSignerBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_RETURN(COSE_Sign_AddSigner(hSign, hSigner, &cose_error),
		COSE_ERR_NONE, CFails++);

	CHECK_FAILURE(COSE_Sign_add_signer(hSignNULL, cn, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_add_signer(hSignBad, cn, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_add_signer(hSign, nullptr, 0, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign_GetSigner(hSignNULL, 1, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_GetSigner(hSignBad, 1, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_GetSigner(hSign, 2, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign_Sign(hSignNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_Sign(hSignBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(COSE_Sign_validate(hSignNULL, hSigner, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_validate(hSignBad, hSigner, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_validate(hSign, hSignerNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_validate(hSign, hSignerBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(COSE_Signer_SetKey(hSignerNULL, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Signer_SetKey(hSignerBad, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Signer_SetKey(hSigner, nullptr, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(
		COSE_Signer_map_get_int(hSignerNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Signer_map_get_int(hSignerBad, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Signer_map_get_int(hSigner, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Signer_map_put_int(
					  hSignerNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Signer_map_put_int(
					  hSignerBad, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Signer_map_put_int(
					  hSigner, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Signer_map_put_int(hSigner, 1, cn,
					  COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(
		COSE_Signer_SetExternal(hSignerNULL, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Signer_SetExternal(hSignerBad, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	COSE_Sign_Free(hSign);
	COSE_Signer_Free(hSigner);
	//
	//  Unsupported algorithm

	hSign = COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSign == nullptr) {
		CFails++;
	}
	hSigner = COSE_Signer_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSigner == nullptr) {
		CFails++;
	}

	if (!COSE_Sign_SetContent(hSign, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Signer_map_put_int(hSigner, COSE_Header_Algorithm,
			cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (!COSE_Sign_AddSigner(hSign, hSigner, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Sign_Sign(hSign, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	if (COSE_Sign_GetSigner(hSign, 9, nullptr)) {
		CFails++;
	}
	COSE_Sign_Free(hSign);
	COSE_Signer_Free(hSigner);

	hSign = COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSign == nullptr) {
		CFails++;
	}
	hSigner = COSE_Signer_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSigner == nullptr) {
		CFails++;
	}

	if (!COSE_Sign_SetContent(hSign, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Signer_map_put_int(hSigner, COSE_Header_Algorithm,
			cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (!COSE_Sign_AddSigner(hSign, hSigner, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Sign_Sign(hSign, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	if (COSE_Sign_GetSigner(hSign, 9, nullptr)) {
		CFails++;
	}

	cn = COSE_Signer_map_get_int(
		hSigner, COSE_Header_Algorithm, COSE_BOTH, &cose_error);
	if (cn != nullptr) {
		if (cn->type != CN_CBOR_TEXT) {
			CFails++;
		}
	}
	else {
		CFails++;
	}

	return;
}
#endif

#if INCLUDE_SIGN1
void Sign1_Corners()
{
	HCOSE_SIGN1 hSign = nullptr;
	HCOSE_SIGN1 hSignNULL = nullptr;
	HCOSE_SIGN1 hSignBad;

	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cose_errback cose_error;

	hSign =
		COSE_Sign1_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#if INCLUDE_SIGN
	hSignBad = (HCOSE_SIGN1)COSE_Sign_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hSignBad = (HCOSE_SIGN1)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	//  Look for invalid parameter
	//		Null handle checks
	//		bad handle checks
	//		null pointers

	CHECK_FAILURE(COSE_Sign1_SetContent(hSignNULL, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_SetContent(hSignBad, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_SetContent(hSign, nullptr, 10, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign1_map_get_int(hSignNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_map_get_int(hSignBad, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_map_get_int(hSign, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign1_map_put_int(
					  hSignNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Sign1_map_put_int(hSignBad, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Sign1_map_put_int(hSign, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Sign1_map_put_int(hSign, 1, cn,
					  COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign1_Sign(hSignNULL, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_Sign(hSignBad, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_Sign(hSign, nullptr, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Sign1_validate(hSignNULL, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_validate(hSignBad, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign1_validate(hSign, nullptr, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(
		COSE_Sign1_SetExternal(hSignNULL, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Sign1_SetExternal(hSignBad, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	COSE_Sign1_Free(hSign);

	//
	//  Unsupported algorithm

	hSign =
		COSE_Sign1_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSign == nullptr) {
		CFails++;
	}

	cn = cn_cbor_int_create(15, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (!COSE_Sign1_SetContent(hSign, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Sign1_map_put_int(hSign, COSE_Header_Algorithm,
			cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Sign1_Sign(hSign, cn, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Sign1_Free(hSign);

	hSign =
		COSE_Sign1_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSign == nullptr) {
		CFails++;
	}

	if (!COSE_Sign1_SetContent(hSign, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}

	if (!COSE_Sign1_map_put_int(hSign, COSE_Header_Algorithm,
			cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Sign1_Sign(hSign, cn, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);

	COSE_Sign1_Free(hSign);
}
#endif
