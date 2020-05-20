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

#include <memory>

#include "test.h"
#include "context.h"
#include "cose_int.h"

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

#if INCLUDE_SIGN
/***  Return:
 *   2 - Success - run the build phase
 *   0 - Failed - don't run the build phase
 *   1 - Failed due to unknown algorithm or other expected failure
 */

int _ValidateSigned(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	int type;
	bool fFailBody = false;
	cose_errback coseError;
	int returnCode = 2;

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		return 0;
	}
	const cn_cbor *pSign = cn_cbor_mapget_string(pInput, "sign");
	if ((pSign == nullptr) || (pSign->type != CN_CBOR_MAP)) {
		return 0;
	}

	const cn_cbor *pSigners = cn_cbor_mapget_string(pSign, "signers");
	if ((pSigners == nullptr) || (pSigners->type != CN_CBOR_ARRAY)) {
		return 0;
	}

	size_t iSigner = pSigners->length - 1;
	pSigners = pSigners->first_child;

	for (; pSigners != nullptr; iSigner--, pSigners = pSigners->next) {
		Safe_HCOSE_SIGN hSig = (HCOSE_SIGN)COSE_Decode(pbEncoded, cbEncoded,
			&type, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hSig == nullptr) {
			return fFailBody ? 1 : 0;
		}

		if (!SetReceivingAttributes(hSig, pSign, Attributes_Sign_protected)) {
			return 0;
		}

		Safe_HCOSE_KEY hkey =
			BuildKey(cn_cbor_mapget_string(pSigners, "key"), false);
		if (hkey == nullptr) {
			return 0;
		}

		Safe_HCOSE_SIGNER hSigner =
			COSE_Sign_GetSigner(hSig, static_cast<int>(iSigner), nullptr);
		if (hSigner == nullptr) {
			return 0;
		}
		if (!SetReceivingAttributes(
				hSigner, pSigners, Attributes_Signer_protected)) {
			return 0;
		}

		if (!COSE_Signer_SetKey2(hSigner, hkey, nullptr)) {
			return 0;
		}

		pFail = cn_cbor_mapget_string(pSigners, "fail");
		if (COSE_Sign_validate(hSig, hSigner, &coseError)) {
			if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
				returnCode = 0;
			}
		}
		else {
			if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
				returnCode = COSE_MIN(1, returnCode);
			}
			else if (fFailBody) {
				returnCode = COSE_MIN(1, returnCode);
			}
			else if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
				returnCode = 0;
			}
			else {
				returnCode = COSE_MIN(1, returnCode);
			}
		}

#if INCLUDE_COUNTERSIGNATURE
		{
			//  Validate counter signatures on signers
			cn_cbor *countersignList =
				cn_cbor_mapget_string(pSigners, "countersign");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					return 0;
				}
				const size_t count = countersigners->length;
				bool forward = true;

				if (COSE_Signer_map_get_int(hSigner, COSE_Header_CounterSign,
						COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
					return 0;
				}

				for (size_t counterNo = 0; counterNo < count; counterNo++) {
					bool noSignAlg = false;

					Safe_HCOSE_COUNTERSIGN h = COSE_Signer_get_countersignature(
						hSigner, static_cast<int>(counterNo), nullptr);
					if (h == nullptr) {
						return 0;
					}

					cn_cbor *counterSigner = cn_cbor_index(countersigners,
						static_cast<int>(
							forward ? counterNo : count - counterNo - 1));

					Safe_HCOSE_KEY hkeyCountersign = BuildKey(
						cn_cbor_mapget_string(counterSigner, "key"), false);
					if (hkeyCountersign == nullptr) {
						return 0;
					}

					if (!COSE_CounterSign_SetKey2(
							h, hkeyCountersign, nullptr)) {
						return 0;
					}

					if (COSE_Signer_CounterSign_validate(
							hSigner, h, &coseError)) {
						//  I don't think we have any forced errors yet.
					}
					else {
						if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
							returnCode = COSE_MIN(1, returnCode);
						}
						else if (forward && counterNo == 0 && count > 1) {
							forward = false;
							counterNo -= 1;
						}
						else {
							returnCode = 0;
						}
					}
				}
			}
		}
#endif

#if INCLUDE_COUNTERSIGNATURE1
		{
			//  Countersign1 on Signer Body

			//  Validate counter signatures on signers
			cn_cbor *countersignList =
				cn_cbor_mapget_string(pSigners, "countersign0");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					return 0;
				}

				if (COSE_Signer_map_get_int(hSigner, COSE_Header_CounterSign1,
						COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
					return 0;
				}

				Safe_HCOSE_COUNTERSIGN1 h(
					COSE_Signer_get_countersignature1(hSigner, nullptr));
				if (h.IsNull()) {
					return 0;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners, 0);

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					return 0;
				}

				if (!COSE_CounterSign1_SetKey(h, hkeyCountersign, nullptr)) {
					return 0;
				}

				if (!SetReceivingAttributes(
						h, counterSigner, Attributes_Countersign1_protected)) {
					return 0;
				}

				if (COSE_Signer_CounterSign1_validate(hSigner, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnCode = COSE_MIN(returnCode, 1);
					}
					else {
						returnCode = 0;
					}
				}
			}
		}
#endif

#if INCLUDE_COUNTERSIGNATURE
		{
			//  Countersign on Signed Body

			if (iSigner == 0) {
				//  Validate counter signatures on signers
				cn_cbor *countersignList =
					cn_cbor_mapget_string(pSign, "countersign");
				if (countersignList != nullptr) {
					cn_cbor *countersigners =
						cn_cbor_mapget_string(countersignList, "signers");
					if (countersigners == nullptr) {
						return 0;
					}
					int count = static_cast<int>(countersigners->length);
					bool forward = true;

					if (COSE_Sign_map_get_int(hSig, COSE_Header_CounterSign,
							COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
						return 0;
					}

					for (int counterNo = 0; counterNo < count; counterNo++) {
						Safe_HCOSE_COUNTERSIGN h =
							COSE_Sign_get_countersignature(
								hSig, counterNo, nullptr);
						if (h == nullptr) {
							returnCode = 0;
							continue;
						}

						cn_cbor *counterSigner = cn_cbor_index(countersigners,
							forward ? counterNo : count - counterNo - 1);

						Safe_HCOSE_KEY hkeyCountersign = BuildKey(
							cn_cbor_mapget_string(counterSigner, "key"), false);
						if (hkeyCountersign == nullptr) {
							returnCode = 0;
							continue;
						}

						if (!COSE_CounterSign_SetKey2(
								h, hkeyCountersign, nullptr)) {
							return 0;
						}

						if (COSE_Sign_CounterSign_validate(
								hSig, h, &coseError)) {
							//  I don't think we have any forced errors yet.
						}
						else {
							if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
								return -1;
							}

							if (forward && counterNo == 0 && count > 1) {
								forward = false;
								counterNo -= 1;
							}
							else {
								returnCode = 0;
							}
						}
					}
				}
			}
		}
#endif

#if INCLUDE_COUNTERSIGNATURE1
		{
			//  Countersign1 on Sign Body

			//  Validate counter signatures on signers
			cn_cbor *countersignList =
				cn_cbor_mapget_string(pSign, "countersign0");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					return 0;
				}

				if (COSE_Sign_map_get_int(hSig, COSE_Header_CounterSign1,
						COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
					return 0;
				}

				bool noSupportSign = false;

				Safe_HCOSE_COUNTERSIGN1 h(
					COSE_Sign_get_countersignature1(hSig, nullptr));
				if (h.IsNull()) {
					return 0;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners, 0);

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					return 0;
				}

				if (!COSE_CounterSign1_SetKey(h, hkeyCountersign, nullptr)) {
					return 0;
				}

				if (!SetReceivingAttributes(
						h, counterSigner, Attributes_Countersign1_protected)) {
					return 0;
				}

				if (COSE_Sign_CounterSign1_validate(hSig, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						return 1;
					}
					return 0;
				}
			}
		}

#endif
	}

	return returnCode;
}

bool ValidateSigned(const cn_cbor *pControl)
{
	int cbEncoded;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	int i = _ValidateSigned(pControl, pbEncoded, cbEncoded);
	if (i == 0) {
		CFails += 1;
	}
	return i == 2;
}

bool BuildSignedMessage(const cn_cbor *pControl)
{
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return false;
	}

	Safe_HCOSE_SIGN hSignObj =
		COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		CFails += 1;
		return false;
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

	if (!SetSendingAttributes(hSignObj, pSign, Attributes_Sign_protected)) {
		goto returnError;
	}

	const cn_cbor *pSigners = cn_cbor_mapget_string(pSign, "signers");
	if ((pSigners == nullptr) || (pSigners->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pSigners = pSigners->first_child;
	for (int iSigner = 0; pSigners != nullptr;
		 iSigner++, pSigners = pSigners->next) {
		Safe_HCOSE_KEY hkey =
			BuildKey(cn_cbor_mapget_string(pSigners, "key"), false);
		if (hkey == nullptr) {
			goto returnError;
		}

		Safe_HCOSE_SIGNER hSigner =
			COSE_Signer_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hSigner == nullptr) {
			goto returnError;
		}

		if (!SetSendingAttributes(
				hSigner, pSigners, Attributes_Signer_protected)) {
			goto returnError;
		}

		if (!COSE_Signer_SetKey2(hSigner, hkey, nullptr)) {
			goto returnError;
		}

		if (!COSE_Sign_AddSigner(hSignObj, hSigner, nullptr)) {
			goto returnError;
		}

#if INCLUDE_COUNTERSIGNATURE
		{
			//  On the signer object
			cn_cbor *countersigns =
				cn_cbor_mapget_string(pSigners, "countersign");
			if (countersigns != nullptr) {
				countersigns = cn_cbor_mapget_string(countersigns, "signers");
				cn_cbor *countersign = countersigns->first_child;

				for (; countersign != nullptr;
					 countersign = countersign->next) {
					Safe_HCOSE_KEY hkeyCountersign = BuildKey(
						cn_cbor_mapget_string(countersign, "key"), false);
					if (hkeyCountersign == nullptr) {
						goto returnError;
					}

					Safe_HCOSE_COUNTERSIGN hCountersign =
						COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
					if (hCountersign == nullptr) {
						goto returnError;
					}

					if (!SetSendingAttributes(hCountersign, countersign,
							Attributes_Countersign_protected)) {
						goto returnError;
					}

					if (!COSE_CounterSign_SetKey2(
							hCountersign, hkeyCountersign, nullptr)) {
						goto returnError;
					}

					if (!COSE_Signer_add_countersignature(
							hSigner, hCountersign, nullptr)) {
						goto returnError;
					}
				}
			}
		}
#endif
#if INCLUDE_COUNTERSIGNATURE1
		{
			//  On the signer object
			cn_cbor *countersigns =
				cn_cbor_mapget_string(pSigners, "countersign0");
			if (countersigns != nullptr) {
				countersigns = cn_cbor_mapget_string(countersigns, "signers");
				cn_cbor *countersign = countersigns->first_child;

				Safe_HCOSE_KEY hkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (hkeyCountersign == nullptr) {
					goto returnError;
				}

				Safe_HCOSE_COUNTERSIGN1 hCountersign =
					COSE_CounterSign1_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
				if (hCountersign == nullptr) {
					goto returnError;
				}

				if (!SetSendingAttributes(hCountersign, countersign,
						Attributes_Countersign1_protected)) {
					goto returnError;
				}

				if (!COSE_CounterSign1_SetKey(
						hCountersign, hkeyCountersign, nullptr)) {
					goto returnError;
				}

				if (!COSE_Signer_add_countersignature1(
						hSigner, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
#endif
	}
#if INCLUDE_COUNTERSIGNATURE
	// On the sign body
	cn_cbor *countersigns1 = cn_cbor_mapget_string(pSign, "countersign");
	if (countersigns1 != nullptr) {
		countersigns1 = cn_cbor_mapget_string(countersigns1, "signers");
		cn_cbor *countersign = countersigns1->first_child;

		for (; countersign != nullptr; countersign = countersign->next) {
			Safe_HCOSE_KEY hkeyCountersign =
				BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
			if (hkeyCountersign == nullptr) {
				goto returnError;
			}

			Safe_HCOSE_COUNTERSIGN hCountersign =
				COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (hCountersign == nullptr) {
				goto returnError;
			}

			if (!SetSendingAttributes(hCountersign, countersign,
					Attributes_Countersign_protected)) {
				goto returnError;
			}

			if (!COSE_CounterSign_SetKey2(
					hCountersign, hkeyCountersign, nullptr)) {
				goto returnError;
			}

			if (!COSE_Sign_add_countersignature(
					hSignObj, hCountersign, nullptr)) {
				goto returnError;
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		//  On the signer object
		cn_cbor *countersigns = cn_cbor_mapget_string(pSign, "countersign0");
		if (countersigns != nullptr) {
			countersigns = cn_cbor_mapget_string(countersigns, "signers");
			cn_cbor *countersign = countersigns->first_child;

			Safe_HCOSE_KEY hkeyCountersign =
				BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
			if (hkeyCountersign == nullptr) {
				goto returnError;
			}

			Safe_HCOSE_COUNTERSIGN1 hCountersign =
				COSE_CounterSign1_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
			if (hCountersign == nullptr) {
				goto returnError;
			}

			if (!SetSendingAttributes(hCountersign, countersign,
					Attributes_Countersign1_protected)) {
				goto returnError;
			}

			if (!COSE_CounterSign1_SetKey(
					hCountersign, hkeyCountersign, nullptr)) {
				goto returnError;
			}

			if (!COSE_Sign_add_countersignature1(
					hSignObj, hCountersign, nullptr)) {
				goto returnError;
			}
		}
	}
#endif

	if (!COSE_Sign_Sign(hSignObj, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode(hSignObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hSignObj.ToCOSE(), rgb.get(), 0, cb);

	COSE_Sign_Free(hSignObj);

	int f = _ValidateSigned(pControl, rgb.get(), cb);
	if (f == 0) {
		CFails += 1;
	}

	return f == 2;
}

int SignMessage()
{
	Safe_HCOSE_SIGN hEncObj = (HCOSE_SIGN)COSE_Sign_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	const char *sz = "This is the content to be used";
	size_t cb;

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
		cn_cbor_data_create(
			rgbX, sizeof(rgbX), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, -3,
		cn_cbor_data_create(
			rgbY, sizeof(rgbY), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, COSE_Key_ID,
		cn_cbor_data_create(kid, sizeof(kid), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	cn_cbor_mapput_int(pkey, -4,
		cn_cbor_data_create(
			rgbD, sizeof(rgbD), CBOR_CONTEXT_PARAM_COMMA nullptr),
		CBOR_CONTEXT_PARAM_COMMA nullptr);

	COSE_Sign_SetContent(
		hEncObj, reinterpret_cast<const byte *>(sz), strlen(sz), nullptr);
	COSE_Signer_Free(COSE_Sign_add_signer(
		hEncObj, pkey, COSE_Algorithm_ECDSA_SHA_256, nullptr));

	COSE_Sign_Sign(hEncObj, nullptr);

	cb = COSE_Encode(hEncObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hEncObj.ToCOSE(), rgb.get(), 0, cb);

	COSE_Sign_Free(hEncObj);

	/* */

	int typ;
	hEncObj = (HCOSE_SIGN)COSE_Decode(rgb.get(), (int)cb, &typ,
		COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA nullptr);

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
	int type;
	bool fFail = false;
	bool fFailBody = false;
	int returnCode = 2;

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		return 0;
	}
	const cn_cbor *pSign = cn_cbor_mapget_string(pInput, "sign0");
	if ((pSign == nullptr) || (pSign->type != CN_CBOR_MAP)) {
		return 0;
	}

	Safe_HCOSE_SIGN1 hSig = (HCOSE_SIGN1)COSE_Decode(pbEncoded, cbEncoded,
		&type, COSE_sign1_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hSig == nullptr) {
		if (fFailBody) {
			return 1;
		}
		return 0;
	}

	if (!SetReceivingAttributes(hSig, pSign, Attributes_Sign1_protected)) {
		return 0;
	}

	Safe_HCOSE_KEY hkey = BuildKey(cn_cbor_mapget_string(pSign, "key"), false);
	if (hkey == nullptr) {
		return 0;
	}

	cose_errback coseError;

	pFail = cn_cbor_mapget_string(pInput, "fail");
	if (COSE_Sign1_validate2(hSig, hkey, &coseError)) {
		if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
			return 0;
		}
	}
	else {
		if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
			return 1;
		}
		if (fFailBody) {
			return 1;
		}

		if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
			return 0;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		//  Countersign on Signed Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList = cn_cbor_mapget_string(pSign, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			size_t count = countersigners->length;
			bool forward = true;

			if (COSE_Sign1_map_get_int(hSig, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			for (size_t counterNo = 0; counterNo < count; counterNo++) {
				bool noSignAlg = false;

				Safe_HCOSE_COUNTERSIGN h = COSE_Sign1_get_countersignature(
					hSig, static_cast<int>(counterNo), nullptr);
				if (h == nullptr) {
					return 0;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners,
					static_cast<int>(
						forward ? counterNo : count - counterNo - 1));

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					return 0;
				}

				if (!COSE_CounterSign_SetKey2(h, hkeyCountersign, nullptr)) {
					return 0;
				}

				if (COSE_Sign1_CounterSign_validate(hSig, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						return 1;
					}

					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
					}
					else {
						return 0;
					}
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		//  Countersign on Signed Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList = cn_cbor_mapget_string(pSign, "countersign0");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			size_t count = countersigners->length;
			bool forward = true;

			if (COSE_Sign1_map_get_int(hSig, COSE_Header_CounterSign1,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			for (size_t counterNo = 0; counterNo < count; counterNo++) {
				bool noSignAlg = false;

				Safe_HCOSE_COUNTERSIGN1 h =
					COSE_Sign1_get_countersignature1(hSig, nullptr);
				if (h == nullptr) {
					return 0;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners,
					static_cast<int>(
						forward ? counterNo : count - counterNo - 1));

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					return 0;
				}

				if (!COSE_CounterSign1_SetKey(h, hkeyCountersign, nullptr)) {
					return 0;
				}

				if (!SetReceivingAttributes(
						h, counterSigner, Attributes_Countersign1_protected)) {
					return 0;
				}

				if (COSE_Sign1_CounterSign1_validate(hSig, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						return 1;
					}

					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
					}
					else {
						return 0;
					}
				}
			}
		}
	}
#endif

	return returnCode;
}

bool ValidateSign1(const cn_cbor *pControl)
{
	int cbEncoded = 0;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	int i = _ValidateSign1(pControl, pbEncoded, cbEncoded);
	if (i == 0) {
		CFails += 1;
	}

	return i == 2;
}

bool BuildSign1Message(const cn_cbor *pControl)
{
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return false;
	}

	Safe_HCOSE_SIGN1 hSignObj =
		COSE_Sign1_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		CFails += 1;
		return false;
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

	if (!SetSendingAttributes(hSignObj, pSign, Attributes_Sign1_protected)) {
		goto returnError;
	}

	Safe_HCOSE_KEY hkey = BuildKey(cn_cbor_mapget_string(pSign, "key"), false);
	if (hkey == nullptr) {
		goto returnError;
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		// On the sign body
		cn_cbor *countersigns = cn_cbor_mapget_string(pSign, "countersign");
		if (countersigns != nullptr) {
			countersigns = cn_cbor_mapget_string(countersigns, "signers");
			cn_cbor *countersign = countersigns->first_child;

			for (; countersign != nullptr; countersign = countersign->next) {
				Safe_HCOSE_KEY hkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (hkeyCountersign == nullptr) {
					goto returnError;
				}

				Safe_HCOSE_COUNTERSIGN hCountersign =
					COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
				if (hCountersign == nullptr) {
					goto returnError;
				}

				if (!SetSendingAttributes(hCountersign, countersign,
						Attributes_Countersign_protected)) {
					goto returnError;
				}

				if (!COSE_CounterSign_SetKey2(
						hCountersign, hkeyCountersign, nullptr)) {
					goto returnError;
				}

				if (!COSE_Sign1_add_countersignature(
						hSignObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		// On the sign body
		cn_cbor *countersigns = cn_cbor_mapget_string(pSign, "countersign0");
		if (countersigns != nullptr) {
			countersigns = cn_cbor_mapget_string(countersigns, "signers");
			cn_cbor *countersign = countersigns->first_child;

			for (; countersign != nullptr; countersign = countersign->next) {
				Safe_HCOSE_KEY hkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (hkeyCountersign == nullptr) {
					goto returnError;
				}

				Safe_HCOSE_COUNTERSIGN1 hCountersign =
					COSE_CounterSign1_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
				if (hCountersign == nullptr) {
					goto returnError;
				}

				if (!SetSendingAttributes(hCountersign, countersign,
						Attributes_Countersign1_protected)) {
					goto returnError;
				}

				if (!COSE_CounterSign1_SetKey(
						hCountersign, hkeyCountersign, nullptr)) {
					goto returnError;
				}

				if (!COSE_Sign1_add_countersignature1(
						hSignObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

	if (!COSE_Sign1_Sign2(hSignObj, hkey, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode(hSignObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hSignObj.ToCOSE(), rgb.get(), 0, cb);

	int f = _ValidateSign1(pControl, rgb.get(), cb);
	if (f == 0) {
		CFails += 1;
	}

	return f == 2;
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

	hSign =
		COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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
	//      nullptr handle
	//      wrong type of handle
	//  nullptr handle checks

	CHECK_FAILURE(
		COSE_Sign_SetContent(hSignNULL, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Sign_SetContent(hSignBad, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Sign_SetContent(hSign, nullptr, sizeof(rgb), &cose_error),
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
	CHECK_FAILURE(COSE_Sign_map_put_int(
					  hSign, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
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

	hSign =
		COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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

	hSign =
		COSE_Sign_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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
	//		nullptr handle checks
	//		bad handle checks
	//		nullptr pointers

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
	CHECK_FAILURE(COSE_Sign1_map_put_int(
					  hSign, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
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
