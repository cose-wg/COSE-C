#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <cose/cose.h>
#include <cose/cose_configure.h>
#include <cn-cbor/cn-cbor.h>
#if (INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0 || INCLUDE_MAC) && \
	(!INCLUDE_MAC || !INCLUDE_SIGN)
#include <cose_int.h>
#endif
#include "test.h"
#include "context.h"
#include "cose_int.h"
#include "utils.hpp"

using namespace cose;

#ifdef _MSC_VER
#pragma warning(disable : 4127)
#endif

#if INCLUDE_ENCRYPT
//  Return 1=expected failure, 0 = failure, 2 = success
int DecryptMessage(const byte *pbEncoded,
	size_t cbEncoded,
	bool fFailBody,
	const cn_cbor *pEnveloped,
	const cn_cbor *pRecipient1,
	int iRecipient1,
	const cn_cbor *pRecipient2,
	int iRecipient2)
{
	int type = 0;
	cose_errback cose_err;
	bool fNoSupport = false;
	int returnValue = 2;

	Safe_HCOSE_ENVELOPED hEnc =
		reinterpret_cast<HCOSE_ENVELOPED>(COSE_Decode(pbEncoded, cbEncoded,
			&type, COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA & cose_err));
	if (hEnc.IsNull()) {
		if (fFailBody && (cose_err.err == COSE_ERR_INVALID_PARAMETER)) {
			return 1;
		}
		return 0;
	}

	if (!SetReceivingAttributes(
			hEnc, pEnveloped, Attributes_Enveloped_protected)) {
		return 0;
	}

	cn_cbor *alg = COSE_Enveloped_map_get_int(
		hEnc, COSE_Header_Algorithm, COSE_BOTH, nullptr);
	if (!IsAlgorithmSupported(alg)) {
		fNoSupport = true;
	}

	Safe_HCOSE_RECIPIENT hRecip =
		COSE_Enveloped_GetRecipient(hEnc, iRecipient1, nullptr);
	if (hRecip.IsNull()) {
		return 0;
	}
	if (!SetReceivingAttributes(
			hRecip, pRecipient1, Attributes_Recipient_protected)) {
		return 0;
	}

	if (pRecipient2 != nullptr) {
		Safe_HCOSE_KEY hkey =
			BuildKey(cn_cbor_mapget_string(pRecipient2, "key"), false);
		if (hkey == nullptr) {
			return 0;
		}

		Safe_HCOSE_RECIPIENT hRecip2 =
			COSE_Recipient_GetRecipient(hRecip, iRecipient2, nullptr);
		if (hRecip2.IsNull()) {
			return 0;
		}

		if (!SetReceivingAttributes(
				hRecip2, pRecipient2, Attributes_Recipient_protected)) {
			return 0;
		}
		if (!COSE_Recipient_SetKey2(hRecip2, hkey, nullptr)) {
			return 0;
		}

		cn_cbor *cnStatic = cn_cbor_mapget_string(pRecipient2, "sender_key");
		if (cnStatic != nullptr) {
			if (COSE_Recipient_map_get_int(hRecip2, COSE_Header_ECDH_SPK,
					COSE_BOTH, nullptr) == nullptr) {
				Safe_HCOSE_KEY senderKey = BuildKey(cnStatic, true);
				if (senderKey == nullptr) {
					return 0;
				}
				if (!COSE_Recipient_SetSenderKey2(
						hRecip2, senderKey, COSE_DONT_SEND, nullptr)) {
					return 0;
				}
			}
		}

		hRecip.Transfer(&hRecip2);
	}
	else {
		Safe_HCOSE_KEY hkey =
			BuildKey(cn_cbor_mapget_string(pRecipient1, "key"), false);
		if (hkey == nullptr) {
			return 0;
		}
		if (!COSE_Recipient_SetKey2(hRecip, hkey, nullptr)) {
			return 0;
		}

		cn_cbor *cnStatic = cn_cbor_mapget_string(pRecipient1, "sender_key");
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
	}

	if (!fFailBody) {
		cn_cbor *cn = cn_cbor_mapget_string(pRecipient1, "fail");
		if (cn != nullptr && (cn->type == CN_CBOR_TRUE)) {
			fFailBody = true;
		}
		if (fFailBody && (pRecipient2 != nullptr)) {
			cn = cn_cbor_mapget_string(pRecipient2, "fail");
			if (cn != nullptr && (cn->type == CN_CBOR_TRUE)) {
				fFailBody = true;
			}
		}
	}

	if (COSE_Enveloped_decrypt(hEnc, hRecip, &cose_err)) {
		returnValue = COSE_MIN(fFailBody ? 1 : 2, returnValue);
	}
	else {
		if (cose_err.err == COSE_ERR_NO_COMPRESSED_POINTS ||
			cose_err.err == COSE_ERR_UNKNOWN_ALGORITHM) {
			returnValue = COSE_MIN(1, returnValue);
		}
		else if (fNoSupport) {
			returnValue = 0;
		}
		else {
			returnValue = COSE_MIN(fFailBody ? 1 : 0, returnValue);
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		//  Countersign on Recipient Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList =
			cn_cbor_mapget_string(pRecipient1, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			const int count = (int)countersigners->length;
			bool forward = true;

			if (COSE_Recipient_map_get_int(hRecip, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			for (int counterNo = 0; counterNo < count; counterNo++) {
				bool noSupportSign = false;

				Safe_HCOSE_COUNTERSIGN h = COSE_Recipient_get_countersignature(
					hRecip, counterNo, nullptr);
				if (h.IsNull()) {
					returnValue = 0;
					continue;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners,
					forward ? counterNo : count - counterNo - 1);

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					returnValue = 0;
					continue;
				}

				if (!COSE_CounterSign_SetKey2(h, hkeyCountersign, nullptr)) {
					returnValue = 0;
					continue;
				}

				cose_errback coseError;

				if (COSE_Recipient_CounterSign_validate(
						hRecip, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnValue = COSE_MIN(1, returnValue);
						continue;
					}

					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
						continue;
					}
					returnValue = 0;
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
			cn_cbor_mapget_string(pRecipient1, "countersign0");
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

			Safe_HCOSE_COUNTERSIGN1 h(
				COSE_Recipient_get_countersignature1(hRecip, nullptr));
			if (h.IsNull()) {
				return 0;
			}

			cn_cbor *counterSigner = cn_cbor_index(countersigners, 0);

			Safe_HCOSE_KEY hkeyCountersign =
				BuildKey(cn_cbor_mapget_string(counterSigner, "key"), false);
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

			cose_errback coseError;
			if (COSE_Recipient_CounterSign1_validate(hRecip, h, &coseError)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
					returnValue = COSE_MIN(1, returnValue);
				}
				else {
					returnValue = 0;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE
	{
		//  Countersign on Enveloped Body

		//  Validate counter signatures on signers
		const cn_cbor *countersignList =
			cn_cbor_mapget_string(pEnveloped, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			const int count = (int)countersigners->length;
			bool forward = true;

			if (COSE_Enveloped_map_get_int(hEnc, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return false;
			}

			for (int counterNo = 0; counterNo < count; counterNo++) {
				Safe_HCOSE_COUNTERSIGN h = COSE_Enveloped_get_countersignature(
					hEnc, counterNo, nullptr);
				if (h == nullptr) {
					return 0;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners,
					forward ? counterNo : count - counterNo - 1);

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					returnValue = 0;
					continue;
				}

				if (!COSE_CounterSign_SetKey2(h, hkeyCountersign, nullptr)) {
					returnValue = 0;
					continue;
				}

				cose_errback coseError;

				if (COSE_Enveloped_CounterSign_validate(hEnc, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnValue = COSE_MIN(1, returnValue);
						continue;
					}

					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
						continue;
					}

					returnValue = 0;
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
			cn_cbor_mapget_string(pEnveloped, "countersign0");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}

			if (COSE_Enveloped_map_get_int(hEnc, COSE_Header_CounterSign1,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			bool noSupportSign = false;
			Safe_HCOSE_COUNTERSIGN1 h =
				COSE_Enveloped_get_countersignature1(hEnc, nullptr);
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
				return false;
			}

			if (!SetReceivingAttributes(
					h, counterSigner, Attributes_Countersign1_protected)) {
				return false;
			}

			cose_errback coseError;
			if (COSE_Enveloped_CounterSign1_validate(hEnc, h, &coseError)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
					returnValue = COSE_MIN(1, returnValue);
				}
				else {
					returnValue = 0;
				}
			}
		}
	}
#endif

	if (returnValue == 0) {
		CFails++;
	}
	return returnValue;
}

//  Return 1=expected failure, 0 = failure, 2 = success
int _ValidateEnveloped(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	bool fFailBody = false;
	int passCount = 0;
	int returnValue = 2;

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		return 0;
	}

	const cn_cbor *pEnveloped = cn_cbor_mapget_string(pInput, "enveloped");
	if ((pEnveloped == nullptr) || (pEnveloped->type != CN_CBOR_MAP)) {
		return 0;
	}

	const cn_cbor *pRecipients =
		cn_cbor_mapget_string(pEnveloped, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		return 0;
	}

	int iRecipient = static_cast<int>(pRecipients->length) - 1;
	pRecipients = pRecipients->first_child;
	for (; pRecipients != nullptr;
		 iRecipient--, pRecipients = pRecipients->next) {
		const cn_cbor *pRecip2 =
			cn_cbor_mapget_string(pRecipients, "recipients");
		if (pRecip2 == nullptr) {
			int value = DecryptMessage(pbEncoded, cbEncoded, fFailBody,
				pEnveloped, pRecipients, iRecipient, nullptr, 0);
			returnValue = COSE_MIN(value, returnValue);
		}
		else {
			int iRecipient2 = static_cast<int>(pRecip2->length - 1);
			pRecip2 = pRecip2->first_child;
			for (; pRecip2 != nullptr; pRecip2 = pRecip2->next, iRecipient2--) {
				int value = DecryptMessage(pbEncoded, cbEncoded, fFailBody,
					pEnveloped, pRecipients, iRecipient, pRecip2, iRecipient2);
				returnValue = COSE_MIN(value, returnValue);
			}
		}
	}
	return returnValue;
}

bool ValidateEnveloped(const cn_cbor *pControl)
{
	int cbEncoded;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	int i = _ValidateEnveloped(pControl, pbEncoded, cbEncoded);
	if (i == 0) {
		CFails += 1;
	}
	return i == 2;
}

HCOSE_RECIPIENT BuildRecipient(const cn_cbor *pRecipient)
{
	Safe_HCOSE_RECIPIENT hRecip = COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecip == nullptr) {
		return nullptr;
	}

	if (!SetSendingAttributes(
			hRecip, pRecipient, Attributes_Recipient_protected)) {
		return nullptr;
	}

	cn_cbor *cnKey = cn_cbor_mapget_string(pRecipient, "key");
	if (cnKey != nullptr) {
		Safe_HCOSE_KEY hkey = BuildKey(cnKey, true);
		if (hkey == nullptr) {
			return nullptr;
		}

		if (!COSE_Recipient_SetKey2(hRecip, hkey, nullptr)) {
			return nullptr;
		}
	}

	cnKey = cn_cbor_mapget_string(pRecipient, "recipients");
	if (cnKey != nullptr) {
		for (cnKey = cnKey->first_child; cnKey != nullptr;
			 cnKey = cnKey->next) {
			Safe_HCOSE_RECIPIENT hRecip2 = BuildRecipient(cnKey);
			if (hRecip2 == nullptr) {
				return nullptr;
			}
			if (!COSE_Recipient_AddRecipient(hRecip, hRecip2, nullptr)) {
				return nullptr;
			}
		}
	}

	cn_cbor *pSenderKey = cn_cbor_mapget_string(pRecipient, "sender_key");
	if (pSenderKey != nullptr) {
		Safe_HCOSE_KEY hSendKey = BuildKey(pSenderKey, false);
		cn_cbor *pKid = cn_cbor_mapget_string(pSenderKey, "kid");
		if (!COSE_Recipient_SetSenderKey2(
				hRecip, hSendKey, (pKid == nullptr) ? 2 : 1, nullptr)) {
			return nullptr;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		// On the Recipient
		cn_cbor *countersigns1 =
			cn_cbor_mapget_string(pRecipient, "countersign");
		if (countersigns1 != nullptr) {
			countersigns1 = cn_cbor_mapget_string(countersigns1, "signers");
			cn_cbor *countersign = countersigns1->first_child;

			for (; countersign != nullptr; countersign = countersign->next) {
				Safe_HCOSE_KEY hkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (hkeyCountersign == nullptr) {
					return nullptr;
				}

				Safe_HCOSE_COUNTERSIGN hCountersign =
					COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
				if (hCountersign == nullptr) {
					return nullptr;
				}

				if (!SetSendingAttributes(hCountersign, countersign,
						Attributes_Countersign_protected)) {
					return nullptr;
				}

				if (!COSE_CounterSign_SetKey2(
						hCountersign, hkeyCountersign, nullptr)) {
					return nullptr;
				}

				if (!COSE_Recipient_add_countersignature(
						hRecip, hCountersign, nullptr)) {
					return nullptr;
				}
			}
		}
	}

#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		// On the Recipient
		cn_cbor *countersigns2 =
			cn_cbor_mapget_string(pRecipient, "countersign0");
		if (countersigns2 != nullptr) {
			countersigns2 = cn_cbor_mapget_string(countersigns2, "signers");
			cn_cbor *countersign = countersigns2->first_child;

			for (; countersign != nullptr; countersign = countersign->next) {
				Safe_HCOSE_KEY hkeyCountersign =
					BuildKey(cn_cbor_mapget_string(countersign, "key"), false);
				if (hkeyCountersign == nullptr) {
					return nullptr;
				}

				Safe_HCOSE_COUNTERSIGN1 hCountersign1;
				hCountersign1.Set(
					COSE_CounterSign1_Init(CBOR_CONTEXT_PARAM_COMMA nullptr));
				if (hCountersign1.IsNull()) {
					return nullptr;
				}

				if (!SetSendingAttributes(hCountersign1, countersign,
						Attributes_Countersign1_protected)) {
					return nullptr;
				}

				if (!COSE_CounterSign1_SetKey(
						hCountersign1, hkeyCountersign, nullptr)) {
					return nullptr;
				}

				if (!COSE_Recipient_add_countersignature1(
						hRecip, hCountersign1, nullptr)) {
					return nullptr;
				}
			}
		}
	}
#endif

	HCOSE_RECIPIENT r = hRecip;
	hRecip.Clear();
	return r;
}

bool BuildEnvelopedMessage(const cn_cbor *pControl)
{
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
	returnError:
		CFails += 1;
		return false;
	}

	Safe_HCOSE_ENVELOPED hEncObj = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
		goto returnError;
	}

	const cn_cbor *pEnveloped = cn_cbor_mapget_string(pInputs, "enveloped");
	if (pEnveloped == nullptr) {
		goto returnError;
	}

	const cn_cbor *pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Enveloped_SetContent(
			hEncObj, pContent->v.bytes, pContent->length, nullptr)) {
		goto returnError;
	}

	if (!SetSendingAttributes(
			hEncObj, pEnveloped, Attributes_Enveloped_protected)) {
		goto returnError;
	}

	const cn_cbor *pRecipients =
		cn_cbor_mapget_string(pEnveloped, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pRecipients = pRecipients->first_child;
	for (int iRecipient = 0; pRecipients != nullptr;
		 iRecipient++, pRecipients = pRecipients->next) {
		Safe_HCOSE_RECIPIENT hRecip = BuildRecipient(pRecipients);
		if (hRecip == nullptr) {
			goto returnError;
		}

		if (!COSE_Enveloped_AddRecipient(hEncObj, hRecip, nullptr)) {
			goto returnError;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		// On the Enveloped body
		cn_cbor *countersigns1 =
			cn_cbor_mapget_string(pEnveloped, "countersign");
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

				if (!SetSendingAttributes(hCountersign, countersign,
						Attributes_Countersign_protected)) {
					goto returnError;
				}

				if (!COSE_CounterSign_SetKey2(
						hCountersign, hkeyCountersign, nullptr)) {
					goto returnError;
				}

				if (!COSE_Enveloped_add_countersignature(
						hEncObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		// On the Enveloped body
		cn_cbor *countersigns2 =
			cn_cbor_mapget_string(pEnveloped, "countersign0");
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

				if (!COSE_Enveloped_add_countersignature1(
						hEncObj, hCountersign1, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

	if (!COSE_Enveloped_encrypt(hEncObj, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode(hEncObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hEncObj.ToCOSE(), rgb.get(), 0, cb);

	hEncObj = nullptr;

	int f = _ValidateEnveloped(pControl, rgb.get(), cb);
	if (f == 0) {
		CFails += 1;
	}
	return f == 2;
}

int EncryptMessage()
{
	Safe_HCOSE_ENVELOPED hEncObj = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	byte rgbSecret[128 / 8] = {'a', 'b', 'c'};
	int cbSecret = 128 / 8;
	byte rgbKid[15] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'l',
		'm', 'n', 'o', 'p'};
	int cbKid = 6;
	size_t cb;
	const char *sz = "This is the content to be used";

	if (hEncObj == nullptr) {
	errorReturn:
		CFails++;
		return 0;
	}
	if (!COSE_Enveloped_map_put_int(hEncObj, COSE_Header_Algorithm,
			cn_cbor_int_create(COSE_Algorithm_AES_CCM_16_64_128,
				CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		goto errorReturn;
	}
	if (!COSE_Enveloped_SetContent(
			hEncObj, (const byte *)sz, strlen(sz), nullptr)) {
		goto errorReturn;
	}
	if (!COSE_Enveloped_map_put_int(hEncObj, COSE_Header_IV,
			cn_cbor_data_create(rgbKid, 13, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_UNPROTECT_ONLY, nullptr)) {
		goto errorReturn;
	}

	Safe_HCOSE_RECIPIENT hRecip = COSE_Recipient_from_shared_secret(
		rgbSecret, cbSecret, rgbKid, cbKid, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecip == nullptr) {
		goto errorReturn;
	}
	if (!COSE_Enveloped_AddRecipient(hEncObj, hRecip, nullptr)) {
		goto errorReturn;
	}

	if (!COSE_Enveloped_encrypt(hEncObj, nullptr)) {
		goto errorReturn;
	}

	cb = COSE_Encode(hEncObj.ToCOSE(), nullptr, 0, 0);
	if (cb < 1) {
		goto errorReturn;
	}
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hEncObj.ToCOSE(), rgb.get(), 0, cb);
	if (cb < 1) {
		goto errorReturn;
	}

	hRecip = nullptr;
	hEncObj = nullptr;

	/* */

	int typ;
	hEncObj = (HCOSE_ENVELOPED)COSE_Decode(rgb.get(), (int)cb, &typ,
		COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncObj == nullptr) {
		goto errorReturn;
	}

	int iRecipient = 0;
	do {
		hRecip = COSE_Enveloped_GetRecipient(hEncObj, iRecipient, nullptr);
		if (hRecip == nullptr) {
			break;
		}

		if (!COSE_Recipient_SetKey_secret(
				hRecip, rgbSecret, cbSecret, nullptr, 0, nullptr)) {
			goto errorReturn;
		}

		if (!COSE_Enveloped_decrypt(hEncObj, hRecip, nullptr)) {
			goto errorReturn;
		}

		hRecip = nullptr;

		iRecipient += 1;

	} while (true);

	return 1;
}
#endif

/********************************************/
#if INCLUDE_ENCRYPT0

//  Return 1=expected failure, 0 = failure, 2 = success
int _ValidateEncrypt(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded,
	cn_cbor *pcnEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor *pFail = nullptr;
	const cn_cbor *pEncrypt = nullptr;
	const cn_cbor *pRecipients = nullptr;
	int type;
	bool fFail = false;
	bool fFailBody = false;
	bool fAlgSupport = true;
	int returnValue = 2;

	if (false) {
	returnError:
		CFails += 1;
		return 0;
	}

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		return 0;
	}
	pEncrypt = cn_cbor_mapget_string(pInput, "encrypted");
	if ((pEncrypt == nullptr) || (pEncrypt->type != CN_CBOR_MAP)) {
		return 0;
	}

	pRecipients = cn_cbor_mapget_string(pEncrypt, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		return 0;
	}

	pRecipients = pRecipients->first_child;

	Safe_HCOSE_ENCRYPT hEnc;

	if (pcnEncoded == nullptr) {
		hEnc = (HCOSE_ENCRYPT)COSE_Decode(pbEncoded, cbEncoded, &type,
			COSE_encrypt_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hEnc == nullptr) {
			if (fFailBody) {
				return 1;
			}
			return 0;
		}
	}
	else {
		hEnc = COSE_Encrypt_Init_From_Object(
			pcnEncoded, CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hEnc == nullptr) {
			if (fFailBody) {
				return 1;
			}
			return 0;
		}
	}

	if (!SetReceivingAttributes(hEnc, pEncrypt, Attributes_Encrypt_protected)) {
		return 0;
	}

	Safe_CN_CBOR pkey =
		BuildCborKey(cn_cbor_mapget_string(pRecipients, "key"), true);
	if (pkey == nullptr) {
		return 0;
	}

	cn_cbor *k = cn_cbor_mapget_int(pkey, -1);
	if (k == nullptr) {
		return 0;
	}

	pFail = cn_cbor_mapget_string(pRecipients, "fail");
	cose_errback coseError;
	if (COSE_Encrypt_decrypt(hEnc, k->v.bytes, k->length, &coseError)) {
		if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
			returnValue = 0;
		}

		size_t cb;
		const byte *pb = COSE_Encrypt_GetContent(hEnc, &cb, nullptr);
		// M00TODO - compare content?
	}
	else {
		if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
			returnValue = COSE_MIN(1, returnValue);
		}
		else if (fFailBody) {
			returnValue = COSE_MIN(1, returnValue);
		}
		else if ((pFail != nullptr) && (pFail->type == CN_CBOR_FALSE)) {
			returnValue = COSE_MIN(1, returnValue);
		}
		else {
			returnValue = 0;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	{
		//  Countersign on Encrypt0 Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList =
			cn_cbor_mapget_string(pEncrypt, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}
			const int count = (int)countersigners->length;
			bool forward = true;

			if (COSE_Encrypt_map_get_int(hEnc, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				goto returnError;
			}

			for (int counterNo = 0; counterNo < count; counterNo++) {
				bool noSupportSign = false;
				bool failThis = false;

				Safe_HCOSE_COUNTERSIGN h = COSE_Encrypt0_get_countersignature(
					hEnc, counterNo, nullptr);
				if (h == nullptr) {
					fFail = true;
					continue;
				}

				cn_cbor *counterSigner = cn_cbor_index(countersigners,
					forward ? counterNo : count - counterNo - 1);

				Safe_HCOSE_KEY hkeyCountersign = BuildKey(
					cn_cbor_mapget_string(counterSigner, "key"), false);
				if (hkeyCountersign == nullptr) {
					returnValue = 0;
					continue;
				}

				if (!COSE_CounterSign_SetKey2(h, hkeyCountersign, nullptr)) {
					fFail = true;
					continue;
				}

				if (COSE_Encrypt0_CounterSign_validate(hEnc, h, &coseError)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
						returnValue = COSE_MIN(1, returnValue);
					}
					else if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
					}
					else {
						returnValue = 0;
					}
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
			cn_cbor_mapget_string(pEncrypt, "countersign0");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				return 0;
			}

			if (COSE_Encrypt_map_get_int(hEnc, COSE_Header_CounterSign1,
					COSE_UNPROTECT_ONLY, nullptr) == nullptr) {
				return 0;
			}

			bool noSupportSign = false;
			Safe_HCOSE_COUNTERSIGN1 h =
				COSE_Encrypt0_get_countersignature1(hEnc, nullptr);
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
				return false;
			}

			if (!SetReceivingAttributes(
					h, counterSigner, Attributes_Countersign1_protected)) {
				return false;
			}

			if (COSE_Encrypt0_CounterSign1_validate(hEnc, h, &coseError)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (coseError.err == COSE_ERR_UNKNOWN_ALGORITHM) {
					returnValue = COSE_MIN(1, returnValue);
				}
				else {
					returnValue = 0;
				}
			}
		}
	}
#endif

	return returnValue;
}

bool ValidateEncrypt(const cn_cbor *pControl)
{
	int cbEncoded;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	int fRet = _ValidateEncrypt(pControl, pbEncoded, cbEncoded, nullptr);
	if (fRet == 0) {
		CFails += 1;
	}
	if (fRet != 2) {
		return false;
	}

	cn_cbor *cbor =
		cn_cbor_decode(pbEncoded, cbEncoded, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (cbor == nullptr) {
		return false;
	}

	fRet = _ValidateEncrypt(pControl, nullptr, 0, cbor);
	if (fRet == 0) {
		CFails += 1;
	}
	return fRet == 2;
}

bool BuildEncryptMessage(const cn_cbor *pControl)
{
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return false;
	}

	Safe_HCOSE_ENCRYPT hEncObj = COSE_Encrypt_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		CFails += 1;
		return false;
	}

	const cn_cbor *pEncrypt = cn_cbor_mapget_string(pInputs, "encrypted");
	if (pEncrypt == nullptr) {
		goto returnError;
	}

	const cn_cbor *pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Encrypt_SetContent(
			hEncObj, pContent->v.bytes, pContent->length, nullptr)) {
		goto returnError;
	}

	if (!SetSendingAttributes(
			hEncObj, pEncrypt, Attributes_Encrypt_protected)) {
		goto returnError;
	}

	const cn_cbor *pRecipients = cn_cbor_mapget_string(pEncrypt, "recipients");
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
		// On the Encrypt0 body
		cn_cbor *countersigns = cn_cbor_mapget_string(pEncrypt, "countersign");
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

				if (!COSE_Encrypt0_add_countersignature(
						hEncObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	{
		// On the Encrypt0 body
		cn_cbor *countersigns = cn_cbor_mapget_string(pEncrypt, "countersign0");
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

				if (!COSE_Encrypt0_add_countersignature1(
						hEncObj, hCountersign, nullptr)) {
					goto returnError;
				}
			}
		}
	}
#endif

	if (!COSE_Encrypt_encrypt(hEncObj, k->v.bytes, k->length, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode(hEncObj.ToCOSE(), nullptr, 0, 0) + 1;
	std::unique_ptr<byte> rgb(new byte[cb]);
	cb = COSE_Encode(hEncObj.ToCOSE(), rgb.get(), 0, cb);

	COSE_Encrypt_Free(hEncObj);

	int f = _ValidateEncrypt(pControl, rgb.get(), cb, nullptr);

	return f == 1;
}
#endif

#if INCLUDE_ENCRYPT
void Enveloped_Corners()
{
	HCOSE_ENVELOPED hEncryptNULL = nullptr;
	HCOSE_ENVELOPED hEncrypt = nullptr;
	HCOSE_ENVELOPED hEncryptBad = nullptr;
	HCOSE_RECIPIENT hRecipientNULL = nullptr;
	HCOSE_RECIPIENT hRecipient = nullptr;
	HCOSE_RECIPIENT hRecipientBad = nullptr;
	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cose_errback cose_error;

	hEncrypt = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#if INCLUDE_MAC
	hEncryptBad = (HCOSE_ENVELOPED)COSE_Mac_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hEncryptBad = (HCOSE_ENVELOPED)COSE_CALLOC(1, sizeof(COSE), context);
#endif
	hRecipient = COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#if INCLUDE_MAC
	hRecipientBad = (HCOSE_RECIPIENT)COSE_Mac_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hRecipientBad = (HCOSE_RECIPIENT)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	//  Missing case - addref then release on item

	//
	//  Do parameter checks
	//      - nullptr handle
	//      - Incorrect handle
	//      - nullptr pointer
	//

	CHECK_FAILURE(COSE_Enveloped_SetContent(hEncryptNULL, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_SetContent(hEncryptBad, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_SetContent(hEncrypt, nullptr, 10, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Enveloped_map_put_int(
					  hEncryptNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_map_put_int(
					  hEncryptBad, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_map_put_int(hEncrypt, 1, cn,
					  COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Enveloped_map_put_int(
					  hEncrypt, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(
		COSE_Enveloped_map_get_int(hEncryptNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Enveloped_map_get_int(hEncryptBad, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(COSE_Enveloped_encrypt(hEncryptNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEncryptBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(COSE_Enveloped_decrypt(hEncryptNULL, hRecipient, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_decrypt(hEncryptBad, hRecipient, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_decrypt(hEncrypt, hRecipientNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_decrypt(hEncrypt, hRecipientBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(
		COSE_Enveloped_AddRecipient(hEncryptNULL, hRecipient, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Enveloped_AddRecipient(hEncryptBad, hRecipient, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Enveloped_AddRecipient(hEncrypt, hRecipientNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Enveloped_AddRecipient(hEncrypt, hRecipientBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncryptNULL, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncryptBad, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(
		COSE_Enveloped_SetExternal(hEncryptNULL, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_SetExternal(hEncryptBad, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Enveloped_SetExternal(hEncrypt, nullptr, 10, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	if (!COSE_Enveloped_Free(hEncrypt)) {
		CFails++;
	}
	if (!COSE_Recipient_Free(hRecipient)) {
		CFails++;
	}

	//
	//  Unsupported algorithm

	//  Bad Int algorithm

	hEncrypt = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncrypt == nullptr) {
		CFails++;
	}
	CHECK_RETURN(
		COSE_Enveloped_SetContent(hEncrypt, (byte *)"Message", 7, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Enveloped_map_put_int(hEncrypt, COSE_Header_Algorithm,
					 cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
					 COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_NONE, CFails++);
	hRecipient = COSE_Recipient_from_shared_secret(
		rgb, sizeof(rgb), rgb, sizeof(rgb), CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecipient == nullptr) {
		CFails++;
	}
	CHECK_RETURN(COSE_Enveloped_AddRecipient(hEncrypt, hRecipient, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEncrypt, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Recipient_Free(hRecipient);
	COSE_Enveloped_Free(hEncrypt);

	hEncrypt = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncrypt == nullptr) {
		CFails++;
	}
	CHECK_RETURN(
		COSE_Enveloped_SetContent(hEncrypt, (byte *)"Message", 7, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(
		COSE_Enveloped_map_put_int(hEncrypt, COSE_Header_Algorithm,
			cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, &cose_error),
		COE_ERR_NONE, CFails++);
	hRecipient = COSE_Recipient_from_shared_secret(
		rgb, sizeof(rgb), rgb, sizeof(rgb), CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hRecipient == nullptr) {
		CFails++;
	}
	CHECK_RETURN(COSE_Enveloped_AddRecipient(hEncrypt, hRecipient, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEncrypt, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);

	//
	//  Over shoot the recipients

	CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncrypt, -1, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncrypt, 9, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	COSE_Enveloped_Free(hEncrypt);
	COSE_Recipient_Free(hRecipient);
}
#endif

#if INCLUDE_ENCRYPT0
void Encrypt_Corners()
{
	HCOSE_ENCRYPT hEncrypt = nullptr;
	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);
	cose_errback cose_error;

	//  Missing case - addref then release on item

	//  nullptr Handle checks

	if (COSE_Encrypt_SetContent(hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_map_get_int(hEncrypt, 1, COSE_BOTH, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_map_put_int(hEncrypt, 1, cn, COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_SetExternal(hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_decrypt(hEncrypt, rgb, sizeof(rgb), nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_Free((HCOSE_ENCRYPT)hEncrypt)) {
		CFails++;
	}

	//  Wrong type of handle checks

#if INCLUDE_MAC
	hEncrypt = (HCOSE_ENCRYPT)COSE_Mac_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
#else
	hEncrypt = (HCOSE_ENCRYPT)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	if (COSE_Encrypt_SetContent(hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_map_get_int(hEncrypt, 1, COSE_BOTH, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_map_put_int(hEncrypt, 1, cn, COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_SetExternal(hEncrypt, rgb, 10, nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_decrypt(hEncrypt, rgb, sizeof(rgb), nullptr)) {
		CFails++;
	}
	if (COSE_Encrypt_Free(hEncrypt)) {
		CFails++;
	}

	//
	//  Unsupported algorithm

	hEncrypt = COSE_Encrypt_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncrypt == nullptr) {
		CFails++;
	}
	if (!COSE_Encrypt_SetContent(hEncrypt, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Encrypt_map_put_int(hEncrypt, COSE_Header_Algorithm,
			cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Encrypt_Free(hEncrypt);

	hEncrypt = COSE_Encrypt_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncrypt == nullptr) {
		CFails++;
	}
	if (!COSE_Encrypt_SetContent(hEncrypt, (byte *)"Message", 7, nullptr)) {
		CFails++;
	}
	if (!COSE_Encrypt_map_put_int(hEncrypt, COSE_Header_Algorithm,
			cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		CFails++;
	}
	CHECK_FAILURE(COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);
	COSE_Encrypt_Free(hEncrypt);
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
void Recipient_Corners()
{
	HCOSE_RECIPIENT hRecip;
	HCOSE_RECIPIENT hRecipNULL = nullptr;
	HCOSE_RECIPIENT hRecipBad;
	cose_errback cose_error;
	byte rgb[10];
	cn_cbor *cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);

	hRecip = COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA & cose_error);
#if INCLUDE_SIGN
	hRecipBad = (HCOSE_RECIPIENT)COSE_Signer_Init(
		CBOR_CONTEXT_PARAM_COMMA & cose_error);
#else
	hRecipBad = (HCOSE_RECIPIENT)COSE_CALLOC(1, sizeof(COSE), context);
#endif

	//  Check for invalid parameters

	CHECK_FAILURE_PTR(COSE_Recipient_from_shared_secret(nullptr, 0, nullptr, 0,
						  CBOR_CONTEXT_PARAM_COMMA & cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Recipient_SetKey_secret(
					  hRecipNULL, rgb, sizeof(rgb), nullptr, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_SetKey_secret(
					  hRecipBad, rgb, sizeof(rgb), nullptr, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_SetKey_secret(
					  hRecip, nullptr, sizeof(rgb), nullptr, 0, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Recipient_SetKey(hRecipNULL, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_FAILURE(COSE_Recipient_SetKey(hRecipBad, cn, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_FAILURE(COSE_Recipient_SetKey(hRecip, nullptr, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Recipient_SetSenderKey(hRecipNULL, cn, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_FAILURE(COSE_Recipient_SetSenderKey(hRecipBad, cn, 0, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_FAILURE(COSE_Recipient_SetSenderKey(hRecip, nullptr, 0, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Recipient_SetSenderKey(hRecip, cn, 3, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_RETURN(COSE_Recipient_SetSenderKey(hRecip, cn, 0, &cose_error),
		COSE_ERR_NONE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);

	CHECK_FAILURE(COSE_Recipient_SetExternal(hRecipNULL, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_SetExternal(hRecipBad, rgb, 10, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	CHECK_FAILURE(
		COSE_Recipient_map_get_int(hRecipNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_Recipient_map_get_int(hRecipBad, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_map_get_int(hRecip, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Recipient_map_put_int(
					  hRecipNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_FAILURE(COSE_Recipient_map_put_int(
					  hRecipBad, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	cn = cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA nullptr);
	CHECK_FAILURE(COSE_Recipient_map_put_int(
					  hRecip, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Recipient_map_put_int(hRecip, 1, cn,
					  COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_Recipient_AddRecipient(hRecipNULL, hRecip, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_AddRecipient(hRecipBad, hRecip, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_AddRecipient(hRecip, hRecipNULL, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Recipient_AddRecipient(hRecip, hRecipBad, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);

	COSE_Recipient_Free(hRecip);

	//  Unknown algorithms
#if INCLUDE_ENCRYPT
	HCOSE_ENVELOPED hEnv = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	hRecip = COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	CHECK_RETURN(COSE_Enveloped_map_put_int(hEnv, COSE_Header_Algorithm,
					 cn_cbor_int_create(COSE_Algorithm_AES_GCM_128,
						 CBOR_CONTEXT_PARAM_COMMA nullptr),
					 COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Enveloped_SetContent(
					 hEnv, (byte *)"This the body", 13, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Recipient_map_put_int(hRecip, COSE_Header_Algorithm,
					 cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA nullptr),
					 COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Enveloped_AddRecipient(hEnv, hRecip, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEnv, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);

	COSE_Enveloped_Free(hEnv);
	COSE_Recipient_Free(hRecip);

	hEnv = COSE_Enveloped_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	hRecip = COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	CHECK_RETURN(COSE_Enveloped_map_put_int(hEnv, COSE_Header_Algorithm,
					 cn_cbor_int_create(COSE_Algorithm_AES_GCM_128,
						 CBOR_CONTEXT_PARAM_COMMA nullptr),
					 COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Enveloped_SetContent(
					 hEnv, (byte *)"This the body", 13, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(
		COSE_Recipient_map_put_int(hRecip, COSE_Header_Algorithm,
			cn_cbor_string_create("Unknown", CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Enveloped_AddRecipient(hEnv, hRecip, &cose_error),
		COSE_ERR_NONE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEnv, &cose_error),
		COSE_ERR_UNKNOWN_ALGORITHM, CFails++);

	COSE_Enveloped_Free(hEnv);
	COSE_Recipient_Free(hRecip);
#endif
}
#endif
