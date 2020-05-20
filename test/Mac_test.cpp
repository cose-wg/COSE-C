#define _CRT_SECURE_NO_WARNINGS

#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cose/cose.h>
#include <cose/cose_configure.h>
#include <cn-cbor/cn-cbor.h>
#include "cose_int.h"
#include "json.h"
#include "test.h"
#include "context.h"

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

#if INCLUDE_MAC
// returns 0=fail;  1= expected fail; 2=success
int _ValidateMAC(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor *pFail;
	const cn_cbor *pMac;
	const cn_cbor *pRecipients;
	Safe_HCOSE_MAC hMAC;
	int type;
	int iRecipient;
	bool fFail = false;
	bool fFailBody = false;
	bool fAlgNoSupport = false;
	int returnCode = 2;
	cose_errback error;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	hMAC = (HCOSE_MAC)COSE_Decode(pbEncoded, cbEncoded, &type, COSE_mac_object,
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		if (fFailBody) {
			return 2;
		}

	failTest:
		CFails += 1;
		return 0;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		return 0;
	}
	pMac = cn_cbor_mapget_string(pInput, "mac");
	if ((pMac == nullptr) || (pMac->type != CN_CBOR_MAP)) {
		return 0;
	}

	if (!SetReceivingAttributes(hMAC, pMac, Attributes_MAC_protected)) {
		return 0;
	}

	pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		return 0;
	}

	iRecipient = (int)pRecipients->length - 1;
	pRecipients = pRecipients->first_child;
	for (; pRecipients != nullptr;
		 iRecipient--, pRecipients = pRecipients->next) {
		fAlgNoSupport = false;
		Safe_HCOSE_KEY hkey =
			BuildKey(cn_cbor_mapget_string(pRecipients, "key"), false);
		if (hkey == nullptr) {
			returnCode = 0;
			continue;
		}

		Safe_HCOSE_RECIPIENT hRecip =
			COSE_Mac_GetRecipient(hMAC, iRecipient, nullptr);
		if (hRecip == nullptr) {
			returnCode = 0;
			continue;
		}

		if (!SetReceivingAttributes(
				hRecip, pRecipients, Attributes_Recipient_protected)) {
			goto failTest;
		}

		if (!COSE_Recipient_SetKey2(hRecip, hkey, nullptr)) {
			returnCode = 0;
			continue;
		}

		cn_cbor *cnStatic = cn_cbor_mapget_string(pRecipients, "sender_key");
		if (cnStatic != nullptr) {
			if (COSE_Recipient_map_get_int(hRecip, COSE_Header_ECDH_SPK,
					COSE_BOTH, nullptr) == nullptr) {
				Safe_HCOSE_KEY senderKey = BuildKey(cnStatic, true);
				if (senderKey == nullptr) {
					return 0;
				}
				if (!COSE_Recipient_SetSenderKey2(
						hRecip, senderKey, COSE_DONT_SEND, nullptr)) {
					return 0;
				}
			}
		}

		pFail = cn_cbor_mapget_string(pRecipients, "fail");

		if (COSE_Mac_validate(hMAC, hRecip, &error)) {
			if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
				returnCode = 0;
			}
		}
		else {
			if (error.err == COSE_ERR_NO_COMPRESSED_POINTS ||
				error.err == COSE_ERR_UNKNOWN_ALGORITHM) {
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
			//  Countersign on Encrypt0 Body

			//  Validate counter signatures on signers
			cn_cbor *countersignList =
				cn_cbor_mapget_string(pRecipients, "countersign");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					return 0;
				}
				int count = static_cast<int>(countersigners->length);
				bool forward = true;

				if (COSE_Recipient_map_get_int(hRecip, COSE_Header_CounterSign,
						COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
					return 0;
				}

				for (int counterNo = 0; counterNo < count; counterNo++) {
					bool noSignSupport = false;
					Safe_HCOSE_COUNTERSIGN h =
						COSE_Recipient_get_countersignature(
							hRecip, counterNo, nullptr);
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
						returnCode = 0;
						continue;
					}

					cose_errback coseError;
					if (COSE_Recipient_CounterSign_validate(
							hRecip, h, &coseError)) {
						//  I don't think we have any forced errors yet.
					}
					else {
						if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
							returnCode = COSE_MIN(returnCode, 1);
							continue;
						}
						if (forward && counterNo == 0 && count > 1) {
							forward = false;
							counterNo -= 1;
							continue;
						}
						returnCode = 0;
					}
				}
			}
		}
#endif

#if INCLUDE_COUNTERSIGNATURE1
		{
			//  Countersign1 on Recipient Body

			//  Validate counter signatures on signers
			const cn_cbor *countersignList =
				cn_cbor_mapget_string(pRecipients, "countersign0");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					return 0;
				}

				if (COSE_Recipient_map_get_int(hRecip, COSE_Header_CounterSign1,
						COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
					return 0;
				}

				bool noSupportSign = false;

				Safe_HCOSE_COUNTERSIGN1 h(
					COSE_Recipient_get_countersignature1(hRecip, nullptr));
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

				cose_errback coseError;
				if (COSE_Recipient_CounterSign1_validate(
						hRecip, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnCode = COSE_MIN(1, returnCode);
					}
					else {
						returnCode = 0;
					}
				}
			}
		}
#endif
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		//  Countersign on Signed Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList = cn_cbor_mapget_string(pMac, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			int count = static_cast<int>(countersigners->length);
			bool forward = true;

			if (COSE_Mac_map_get_int(hMAC, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			for (int counterNo = 0; counterNo < count; counterNo++) {
				bool noSignSupport = false;

				Safe_HCOSE_COUNTERSIGN h =
					COSE_Mac_get_countersignature(hMAC, counterNo, nullptr);
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

				if (!COSE_CounterSign_SetKey2(h, hkeyCountersign, nullptr)) {
					returnCode = 0;
					continue;
				}

				cose_errback coseError;
				if (COSE_Mac_CounterSign_validate(hMAC, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnCode = COSE_MIN(1, returnCode);
						continue;
					}
					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
						continue;
					}

					returnCode = 0;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		//  Countersign1 on Enveloped Body

		//  Validate counter signatures on signers
		const cn_cbor *countersignList =
			cn_cbor_mapget_string(pMac, "countersign0");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}

			if (COSE_Mac_map_get_int(hMAC, COSE_Header_CounterSign1,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			bool noSupportSign = false;
			Safe_HCOSE_COUNTERSIGN1 h =
				COSE_Mac_get_countersignature1(hMAC, nullptr);
			if (h.IsNull()) {
				return 0;
			}

			cn_cbor *counterSigner = cn_cbor_index(countersigners, 0);

			Safe_HCOSE_KEY hkeyCountersign(
				BuildKey(cn_cbor_mapget_string(counterSigner, "key"), false));
			if (hkeyCountersign == nullptr) {
				return 0;
			}

			if (!COSE_CounterSign1_SetKey(h, hkeyCountersign, nullptr)) {
				return 0;
				return false;
			}

			if (!SetReceivingAttributes(
					h, counterSigner, Attributes_Countersign1_protected)) {
				return 0;
			}

			cose_errback coseError;
			if (COSE_Mac_CounterSign1_validate(hMAC, h, &coseError)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
					returnCode = COSE_MIN(1, returnCode);
				}
				else {
					returnCode = 0;
				}
			}
		}
	}
#endif

	return returnCode;
}

bool ValidateMAC(const cn_cbor *pControl)
{
	int cbEncoded = 0;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	int i = _ValidateMAC(pControl, pbEncoded, cbEncoded);
	if (i == 0) {
		CFails += 1;
	}
	return i == 2;
}

bool BuildMacMessage(const cn_cbor *pControl)
{
	int iRecipient = 0;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return false;
	}

	Safe_HCOSE_MAC hMacObj =
		COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		CFails += 1;
		return false;
	}
	const cn_cbor *pMac = cn_cbor_mapget_string(pInputs, "mac");
	if (pMac == nullptr) {
		goto returnError;
	}

	const cn_cbor *pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Mac_SetContent(
			hMacObj, pContent->v.bytes, pContent->length, nullptr)) {
		goto returnError;
	}

	if (!SetSendingAttributes(hMacObj, pMac, Attributes_MAC_protected)) {
		goto returnError;
	}

	const cn_cbor *pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pRecipients = pRecipients->first_child;
	for (iRecipient = 0; pRecipients != nullptr;
		 iRecipient++, pRecipients = pRecipients->next) {
		Safe_HCOSE_KEY hkey =
			BuildKey(cn_cbor_mapget_string(pRecipients, "key"), true);
		if (hkey == nullptr) {
			goto returnError;
		}

		Safe_HCOSE_RECIPIENT hRecip = COSE_Recipient_Init(
			COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hRecip == nullptr) {
			goto returnError;
		}

		if (!SetSendingAttributes(
				hRecip, pRecipients, Attributes_Recipient_protected)) {
			goto returnError;
		}

		if (!COSE_Recipient_SetKey2(hRecip, hkey, nullptr)) {
			goto returnError;
		}

		cn_cbor *pSenderKey = cn_cbor_mapget_string(pRecipients, "sender_key");
		if (pSenderKey != nullptr) {
			Safe_HCOSE_KEY hSendKey = BuildKey(pSenderKey, false);
			if (!COSE_Recipient_SetSenderKey2(hRecip, hSendKey, 2, nullptr)) {
				goto returnError;
			}
		}

		if (!COSE_Mac_AddRecipient(hMacObj, hRecip, nullptr)) {
			goto returnError;
		}

#if INCLUDE_COUNTERSIGNATURE
		{
			// On the Recipient
			cn_cbor *countersigns1 =
				cn_cbor_mapget_string(pRecipients, "countersign");
			if (countersigns1 != nullptr) {
				countersigns1 = cn_cbor_mapget_string(countersigns1, "signers");
				cn_cbor *countersign = countersigns1->first_child;

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

					if (!COSE_Recipient_add_countersignature(
							hRecip, hCountersign, nullptr)) {
						goto returnError;
					}
				}
			}
		}
#endif

#if INCLUDE_COUNTERSIGNATURE1
		{
			//  Countersign1 on Recipient Body

			//  Validate counter signatures on signers
			cn_cbor *countersignList =
				cn_cbor_mapget_string(pRecipients, "countersign0");
			if (countersignList != nullptr) {
				cn_cbor *countersigners =
					cn_cbor_mapget_string(countersignList, "signers");
				if (countersigners == nullptr) {
					goto returnError;
				}

				if (COSE_Recipient_map_get_int(hRecip, COSE_Header_CounterSign1,
						COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
					goto returnError;
				}

				bool noSupportSign = false;

				Safe_HCOSE_COUNTERSIGN1 h(
					COSE_Recipient_get_countersignature1(hRecip, nullptr));
				if (h.IsNull()) {
					goto returnError;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners, 0);

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					goto returnError;
				}

				if (!COSE_CounterSign1_SetKey(h, hkeyCountersign, nullptr)) {
					goto returnError;
				}

				cose_errback coseError;
				if (COSE_Recipient_CounterSign1_validate(
						hRecip, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						return false;
					}
					goto returnError;
				}
			}
		}
#endif
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		// On the Mac body
		cn_cbor *countersigns1 = cn_cbor_mapget_string(pMac, "countersign");
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

				if (!COSE_Mac_add_countersignature(
						hMacObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		// On the Mac body
		cn_cbor *countersigns2 = cn_cbor_mapget_string(pMac, "countersign0");
		if (countersigns2 != nullptr) {
			countersigns2 = cn_cbor_mapget_string(countersigns2, "signers");
			cn_cbor *countersign = countersigns2->first_child;

			for (; countersign != nullptr; countersign = countersign->next) {
				Safe_HCOSE_KEY hkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (hkeyCountersign == nullptr) {
					goto returnError;
				}

				Safe_HCOSE_COUNTERSIGN1 hCountersign1 =
					COSE_CounterSign1_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
				if (hCountersign1.IsNull()) {
					goto returnError;
				}

				if (!SetSendingAttributes(hCountersign1, countersign,
						Attributes_Countersign1_protected)) {
					goto returnError;
				}

				if (!COSE_CounterSign1_SetKey(
						hCountersign1, hkeyCountersign, nullptr)) {
					goto returnError;
				}

				if (!COSE_Mac_add_countersignature1(
						hMacObj, hCountersign1, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

	if (!COSE_Mac_encrypt(hMacObj, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode(hMacObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hMacObj.ToCOSE(), rgb.get(), 0, cb);

	hMacObj = nullptr;

	int f = _ValidateMAC(pControl, rgb.get(), cb);
	if (f == 0) {
		CFails++;
	}
	return f == 2;
}

int MacMessage()
{
	Safe_HCOSE_MAC hEncObj =
		COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	const char *sz = "This is the content to be used";
	byte rgbSecret[256 / 8] = {'a', 'b', 'c'};
	byte rgbKid[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
	int cbKid = 6;
	size_t cb = 0;

	if (hEncObj == nullptr) {
	errorReturn:
		CFails++;
		return 0;
	}

	if (!COSE_Mac_map_put_int(hEncObj, COSE_Header_Algorithm,
			cn_cbor_int_create(
				COSE_Algorithm_HMAC_256_256, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		goto errorReturn;
	}

	if (!COSE_Mac_SetContent(
			hEncObj, reinterpret_cast<const byte *>(sz), strlen(sz), nullptr)) {
		goto errorReturn;
	}

	Safe_HCOSE_RECIPIENT hRecip = COSE_Recipient_from_shared_secret(rgbSecret,
		sizeof(rgbSecret), rgbKid, cbKid, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecip == nullptr) {
		goto errorReturn;
	}

	if (!COSE_Mac_AddRecipient(hEncObj, hRecip, nullptr)) {
		goto errorReturn;
	}

	if (!COSE_Mac_encrypt(hEncObj, nullptr)) {
		goto errorReturn;
	}

	cb = COSE_Encode(hEncObj.ToCOSE(), nullptr, 0, 0);
	if (cb == 0) {
		goto errorReturn;
	}

	std::unique_ptr<byte> rgb(new byte[cb]);
	if (rgb == nullptr) {
		goto errorReturn;
	}
	cb = COSE_Encode(hEncObj.ToCOSE(), rgb.get(), 0, cb);
	if (cb == 0) {
		goto errorReturn;
	}

	int typ;
	hEncObj = (HCOSE_MAC)COSE_Decode(rgb.get(), static_cast<int>(cb), &typ,
		COSE_mac_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncObj == nullptr) {
		goto errorReturn;
	}

	int iRecipient = 0;
	do {
		Safe_HCOSE_RECIPIENT hRecip2;

		hRecip2 = COSE_Mac_GetRecipient(hEncObj, iRecipient, nullptr);
		if (hRecip2 == nullptr) {
			break;
		}

		if (!COSE_Recipient_SetKey_secret(
				hRecip2, rgbSecret, sizeof(rgbSecret), nullptr, 0, nullptr)) {
			goto errorReturn;
		}

		if (!COSE_Mac_validate(hEncObj, hRecip2, nullptr)) {
			goto errorReturn;
		}

		iRecipient += 1;
	} while (true);

	COSE_Mac_Free(hEncObj);

	return 1;
}
#endif

#if INCLUDE_MAC0
int _ValidateMac0(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor *pFail = nullptr;
	const cn_cbor *pMac = nullptr;
	const cn_cbor *pRecipients = nullptr;
	int type;
	bool fFail = false;
	bool fFailBody = false;
	bool fUnsuportedAlg = false;
	int returnCode = 2;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	Safe_HCOSE_MAC0 hMAC = (HCOSE_MAC0)COSE_Decode(pbEncoded, cbEncoded, &type,
		COSE_mac0_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		if (fFailBody) {
			return 1;
		}
		return 0;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		return 0;
	}
	pMac = cn_cbor_mapget_string(pInput, "mac0");
	if ((pMac == nullptr) || (pMac->type != CN_CBOR_MAP)) {
		return 0;
	}

	if (!SetReceivingAttributes(hMAC, pMac, Attributes_MAC0_protected)) {
		return 0;
	}

	pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		return 0;
	}

	pRecipients = pRecipients->first_child;

	Safe_CN_CBOR pkey =
		BuildCborKey(cn_cbor_mapget_string(pRecipients, "key"), true);
	if (pkey == nullptr) {
		return 0;
	}

	cn_cbor *k = cn_cbor_mapget_int(pkey, -1);

	pFail = cn_cbor_mapget_string(pRecipients, "fail");

	cose_errback coseError;
	if (COSE_Mac0_validate(hMAC, k->v.bytes, k->length, &coseError)) {
		if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
			return 0;
		}
	}
	else {
		if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
			returnCode = COSE_MIN(returnCode, 1);
		}
		else if (fFailBody) {
			returnCode = COSE_MIN(returnCode, 1);
		}
		else if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
			return 0;
		}
		else {
			returnCode = COSE_MIN(returnCode, 1);
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		//  Countersign on Mac0 Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList = cn_cbor_mapget_string(pMac, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			const int count = static_cast<int>(countersigners->length);
			bool forward = true;

			if (COSE_Mac0_map_get_int(hMAC, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			for (int counterNo = 0; counterNo < count; counterNo++) {
				Safe_HCOSE_COUNTERSIGN h =
					COSE_Mac0_get_countersignature(hMAC, counterNo, nullptr);
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

				if (!COSE_CounterSign_SetKey2(h, hkeyCountersign, nullptr)) {
					returnCode = 0;
					continue;
				}

				if (COSE_Mac0_CounterSign_validate(hMAC, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnCode = COSE_MIN(returnCode, 1);
						continue;
					}

					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
						continue;
					}
					returnCode = 0;
				}
			}
		}
	}
#endif

#ifdef INCLUDE_COUNTERSIGNATURE1
	{
		//  Countersign on Mac0 Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList = cn_cbor_mapget_string(pMac, "countersign0");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			countersigners = countersigners->first_child;

			if (COSE_Mac0_map_get_int(hMAC, COSE_Header_CounterSign1,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			Safe_HCOSE_COUNTERSIGN1 h =
				COSE_Mac0_get_countersignature1(hMAC, nullptr);
			if (h == nullptr) {
				return 0;
			}

			Safe_HCOSE_KEY hkeyCountersign =
				BuildKey(cn_cbor_mapget_string(countersigners, "key"), false);
			if (hkeyCountersign == nullptr) {
				return 0;
			}

			if (!COSE_CounterSign1_SetKey(h, hkeyCountersign, nullptr)) {
				return 0;
			}

			if (!SetReceivingAttributes(
					h, countersigners, Attributes_Countersign1_protected)) {
				return 0;
			}

			if (COSE_Mac0_CounterSign1_validate(hMAC, h, &coseError)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
					returnCode = COSE_MIN(1, returnCode);
				}
				else {
					return 0;
				}
			}
		}
	}
#endif

	return returnCode;
}

bool ValidateMac0(const cn_cbor *pControl)
{
	int cbEncoded;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	int i = _ValidateMac0(pControl, pbEncoded, cbEncoded);
	if (i == 0) {
		CFails += 1;
	}
	return i == 2;
}

bool BuildMac0Message(const cn_cbor *pControl)
{
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return false;
	}

	Safe_HCOSE_MAC0 hMacObj =
		COSE_Mac0_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		CFails += 1;
		return false;
	}
	const cn_cbor *pMac = cn_cbor_mapget_string(pInputs, "mac0");
	if (pMac == nullptr) {
		goto returnError;
	}

	const cn_cbor *pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Mac0_SetContent(
			hMacObj, pContent->v.bytes, pContent->length, nullptr)) {
		goto returnError;
	}

	if (!SetSendingAttributes(hMacObj, pMac, Attributes_MAC0_protected)) {
		goto returnError;
	}

	const cn_cbor *pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pRecipients = pRecipients->first_child;

	Safe_CN_CBOR pkey =
		BuildCborKey(cn_cbor_mapget_string(pRecipients, "key"), false);
	if (pkey == nullptr) {
		goto returnError;
	}

	cn_cbor *k = cn_cbor_mapget_int(pkey, -1);

#if INCLUDE_COUNTERSIGNATURE
	{
		// On the sign body
		cn_cbor *countersigns = cn_cbor_mapget_string(pMac, "countersign");
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

				if (!COSE_Mac0_add_countersignature(
						hMacObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		// On the sign body
		cn_cbor *countersigns = cn_cbor_mapget_string(pMac, "countersign0");
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

			if (!COSE_Mac0_add_countersignature1(
					hMacObj, hCountersign, nullptr)) {
				goto returnError;
			}
		}
	}

#endif

	if (!COSE_Mac0_encrypt(hMacObj, k->v.bytes, k->length, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode(hMacObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hMacObj.ToCOSE(), rgb.get(), 0, cb);

	hMacObj = nullptr;

	int f = _ValidateMac0(pControl, rgb.get(), cb);
	if (f == 0) {
		CFails++;
	}

	return f == 2;
}
#endif

#if INCLUDE_MAC
void MAC_Corners()
{
	HCOSE_MAC hMAC = nullptr;
	HCOSE_ENCRYPT hEncrypt = nullptr;
	HCOSE_RECIPIENT hRecipient = nullptr;
	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cose_errback cose_error;

	//  Missing case - addref then release on item

	//  Incorrect algorithm

	hMAC = (HCOSE_MAC)COSE_Mac_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	//  Invalid Handle checks

	if (COSE_Mac_SetContent((HCOSE_MAC)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_map_get_int((HCOSE_MAC)hEncrypt, 1, COSE_BOTH, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_map_put_int(
			(HCOSE_MAC)hEncrypt, 1, cn, COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_encrypt((HCOSE_MAC)hEncrypt, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_validate(
			(HCOSE_MAC)hEncrypt, (HCOSE_RECIPIENT)hMAC, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_AddRecipient(
			(HCOSE_MAC)hEncrypt, (HCOSE_RECIPIENT)hMAC, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_GetRecipient((HCOSE_MAC)hEncrypt, 0, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_SetExternal((HCOSE_MAC)hEncrypt, rgb, 0, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_Free((HCOSE_MAC)hEncrypt)) {
		CFails++;
	}

#if INCLUDE_ENCRYPT0
	hEncrypt = COSE_Encrypt_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hEncrypt = (HCOSE_ENCRYPT)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	if (COSE_Mac_SetContent((HCOSE_MAC)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_map_get_int((HCOSE_MAC)hEncrypt, 1, COSE_BOTH, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_map_put_int(
			(HCOSE_MAC)hEncrypt, 1, cn, COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_encrypt((HCOSE_MAC)hEncrypt, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_validate(
			(HCOSE_MAC)hEncrypt, (HCOSE_RECIPIENT)hMAC, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_AddRecipient(
			(HCOSE_MAC)hEncrypt, (HCOSE_RECIPIENT)hMAC, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_GetRecipient((HCOSE_MAC)hEncrypt, 0, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_SetExternal((HCOSE_MAC)hEncrypt, rgb, 0, nullptr)) {
		CFails++;
	}
	if (COSE_Mac_Free((HCOSE_MAC)hEncrypt)) {
		CFails++;
	}

	//
	//  Unsupported algorithm

	hMAC =
		COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		CFails++;
	}
	if (!COSE_Mac_SetContent(hMAC, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Mac_map_put_int(hMAC, COSE_Header_Algorithm,
			cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	hRecipient = COSE_Recipient_from_shared_secret(
		rgb, sizeof(rgb), rgb, sizeof(rgb), CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecipient == nullptr) {
		CFails++;
	}
	if (!COSE_Mac_AddRecipient(hMAC, hRecipient, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Mac_encrypt(hMAC, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Mac_Free(hMAC);
	COSE_Recipient_Free(hRecipient);

	hMAC =
		COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		CFails++;
	}
	if (!COSE_Mac_SetContent(hMAC, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Mac_map_put_int(hMAC, COSE_Header_Algorithm,
			cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	hRecipient = COSE_Recipient_from_shared_secret(
		rgb, sizeof(rgb), rgb, sizeof(rgb), CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecipient == nullptr) {
		CFails++;
	}
	if (!COSE_Mac_AddRecipient(hMAC, hRecipient, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Mac_encrypt(hMAC, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Recipient_Free(hRecipient);
	COSE_Mac_Free(hMAC);

	if (COSE_Mac_GetRecipient(hMAC, 9, nullptr)) {
		CFails++;
	}
}
#endif

#if INCLUDE_MAC0
void MAC0_Corners()
{
	HCOSE_ENCRYPT hEncrypt = nullptr;
	HCOSE_MAC0 hMAC = nullptr;
	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cose_errback cose_error;

	hEncrypt = COSE_Encrypt_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	//  Missing case - addref then release on item

	//  Invalid Handle checks

	if (COSE_Mac0_SetContent((HCOSE_MAC0)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_map_get_int((HCOSE_MAC0)hEncrypt, 1, COSE_BOTH, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_map_put_int(
			(HCOSE_MAC0)hEncrypt, 1, cn, COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_encrypt((HCOSE_MAC0)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_validate((HCOSE_MAC0)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_SetExternal((HCOSE_MAC0)hEncrypt, rgb, 0, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_Free((HCOSE_MAC0)hEncrypt)) {
		CFails++;
	}

	hEncrypt = COSE_Encrypt_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	if (COSE_Mac0_SetContent((HCOSE_MAC0)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_map_get_int((HCOSE_MAC0)hEncrypt, 1, COSE_BOTH, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_map_put_int(
			(HCOSE_MAC0)hEncrypt, 1, cn, COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_encrypt((HCOSE_MAC0)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_validate((HCOSE_MAC0)hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Mac0_SetExternal((HCOSE_MAC0)hEncrypt, rgb, 0, nullptr)) {
		CFails++;
	}

	if (COSE_Mac0_Free((HCOSE_MAC0)hEncrypt)) {
		CFails++;
	}

	//
	//  Unsupported algorithm

	hMAC =
		COSE_Mac0_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		CFails++;
	}
	if (!COSE_Mac0_SetContent(hMAC, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Mac0_map_put_int(hMAC, COSE_Header_Algorithm,
			cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Mac0_encrypt(hMAC, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Mac0_Free(hMAC);

	hMAC =
		COSE_Mac0_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		CFails++;
	}
	if (!COSE_Mac0_SetContent(hMAC, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Mac0_map_put_int(hMAC, COSE_Header_Algorithm,
			cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Mac0_encrypt(hMAC, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Mac0_Free(hMAC);
}
#endif
