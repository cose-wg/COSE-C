#define _CRT_SECURE_NO_WARNINGS

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
int _ValidateMAC(const cn_cbor *pControl,
	const byte *pbEncoded,
	size_t cbEncoded)
{
	const cn_cbor *pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor *pFail;
	const cn_cbor *pMac;
	const cn_cbor *pRecipients;
	HCOSE_MAC hMAC;
	int type;
	int iRecipient;
	bool fFail = false;
	bool fFailBody = false;
	bool fAlgNoSupport = false;
	int returnCode = 1;
	cose_errback error;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	hMAC = (HCOSE_MAC)COSE_Decode(pbEncoded, cbEncoded, &type, COSE_mac_object,
		CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		if (fFailBody) {
			return 0;
		}

	failTest:
		CFails += 1;
		return 0;
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		goto failTest;
	}
	pMac = cn_cbor_mapget_string(pInput, "mac");
	if ((pMac == nullptr) || (pMac->type != CN_CBOR_MAP)) {
		goto failTest;
	}

	if (!SetReceivingAttributes((HCOSE)hMAC, pMac, Attributes_MAC_protected)) {
		goto failTest;
	}

	pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto failTest;
	}

	iRecipient = (int)pRecipients->length - 1;
	pRecipients = pRecipients->first_child;
	for (; pRecipients != nullptr; iRecipient--, pRecipients = pRecipients->next) {
		fAlgNoSupport = false;
		cn_cbor *pkey =
			BuildKey(cn_cbor_mapget_string(pRecipients, "key"), false);
		if (pkey == nullptr) {
			fFail = true;
			continue;
		}

		HCOSE_RECIPIENT hRecip = COSE_Mac_GetRecipient(hMAC, iRecipient, nullptr);
		if (hRecip == nullptr) {
			fFail = true;
			continue;
		}

		if (!SetReceivingAttributes(
				(HCOSE)hRecip, pRecipients, Attributes_Recipient_protected)) {
			COSE_Recipient_Free(hRecip);
			goto failTest;
		}

		if (!COSE_Recipient_SetKey(hRecip, pkey, nullptr)) {
			fFail = true;
			COSE_Recipient_Free(hRecip);
			continue;
		}

		cn_cbor *cnStatic = cn_cbor_mapget_string(pRecipients, "sender_key");
		if (cnStatic != nullptr) {
			if (COSE_Recipient_map_get_int(
					hRecip, COSE_Header_ECDH_SPK, COSE_BOTH, nullptr) == 0) {
				COSE_Recipient_map_put_int(hRecip, COSE_Header_ECDH_SPK,
					BuildKey(cnStatic, true), COSE_DONT_SEND, nullptr);
			}
		}

		pFail = cn_cbor_mapget_string(pRecipients, "fail");

		cn_cbor *alg =
			COSE_Mac_map_get_int(hMAC, COSE_Header_Algorithm, COSE_BOTH, nullptr);
		if (!IsAlgorithmSupported(alg)) {
			fAlgNoSupport = true;
		}

		alg = COSE_Recipient_map_get_int(
			hRecip, COSE_Header_Algorithm, COSE_BOTH, nullptr);
		if (!IsAlgorithmSupported(alg)) {
			fAlgNoSupport = true;
		}

		if (COSE_Mac_validate(hMAC, hRecip, &error)) {
			if (fAlgNoSupport) {
				fFail = true;
			}
			else if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
				fFail = true;
			}
		}
		else {
			if (error.err == COSE_ERR_NO_COMPRESSED_POINTS ||
				error.err == COSE_ERR_UNKNOWN_ALGORITHM) {
				fAlgNoSupport = true;
				returnCode = 0;
			}
			else if (fAlgNoSupport) {
				returnCode = 0;
			}
			else if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
				fFail = true;
			}
		}

#if INCLUDE_COUNTERSIGNATURE
		//  Countersign on Encrypt0 Body

		//  Validate counter signatures on signers
		cn_cbor *countersignList =
			cn_cbor_mapget_string(pRecipients, "countersign");
		if (countersignList != nullptr) {
			cn_cbor *countersigners =
				cn_cbor_mapget_string(countersignList, "signers");
			if (countersigners == nullptr) {
				COSE_Recipient_Free(hRecip);
				goto failTest;
			}
			int count = countersigners->length;
			bool forward = true;

			if (COSE_Recipient_map_get_int(hRecip, COSE_Header_CounterSign,
					COSE_UNPROTECT_ONLY, 0) == nullptr) {
				COSE_Recipient_Free(hRecip);
				goto failTest;
			}

			for (int counterNo = 0; counterNo < count; counterNo++) {
				bool noSignSupport = false;
				HCOSE_COUNTERSIGN h =
					COSE_Recipient_get_countersignature(hRecip, counterNo, 0);
				if (h == nullptr) {
					continue;
				}

				alg = COSE_CounterSign_map_get_int(
					h, COSE_Header_Algorithm, COSE_BOTH, nullptr);
				if (!IsAlgorithmSupported(alg)) {
					fAlgNoSupport = true;
					noSignSupport = true;
					returnCode = 0;
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
					CN_CBOR_FREE(pkeyCountersign, context);
					COSE_CounterSign_Free(h);
					continue;
				}

				if (COSE_Recipient_CounterSign_validate(hRecip, h, 0)) {
					//  I don't think we have any forced errors yet.
				}
				else {
					if (forward && counterNo == 0 && count > 1) {
						forward = false;
						counterNo -= 1;
					}
					else {
						fFail |= !noSignSupport;
					}
				}

				COSE_CounterSign_Free(h);
			}
		}
#endif

		COSE_Recipient_Free(hRecip);
	}

#if INCLUDE_COUNTERSIGNATURE
	//  Countersign on Signed Body

	//  Validate counter signatures on signers
	cn_cbor *countersignList = cn_cbor_mapget_string(pMac, "countersign");
	if (countersignList != nullptr) {
		cn_cbor *countersigners =
			cn_cbor_mapget_string(countersignList, "signers");
		if (countersigners == nullptr) {
			goto failTest;
		}
		int count = countersigners->length;
		bool forward = true;

		if (COSE_Mac_map_get_int(hMAC, COSE_Header_CounterSign,
				COSE_UNPROTECT_ONLY, 0) == nullptr) {
			goto failTest;
		}

		for (int counterNo = 0; counterNo < count; counterNo++) {
			bool noSignSupport = false;

			HCOSE_COUNTERSIGN h =
				COSE_Mac_get_countersignature(hMAC, counterNo, 0);
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

			cn_cbor *alg = COSE_CounterSign_map_get_int(
				h, COSE_Header_Algorithm, COSE_BOTH, nullptr);
			if (!IsAlgorithmSupported(alg)) {
				fAlgNoSupport = true;
				noSignSupport = true;
				returnCode = 0;
			}

			if (COSE_Mac_CounterSign_validate(hMAC, h, 0)) {
				//  I don't think we have any forced errors yet.
			}
			else {
				if (forward && counterNo == 0 && count > 1) {
					forward = false;
					counterNo -= 1;
				}
				else {
					fFail |= !noSignSupport;
				}
			}

			COSE_CounterSign_Free(h);
		}
	}
#endif

	COSE_Mac_Free(hMAC);

	if (fFailBody) {
		if (!fFail) {
			fFail = true;
		}
		else {
			fFail = false;
		}
	}

	if (fFail && !fAlgNoSupport) {
		CFails += 1;
	}
	return returnCode;
}

int ValidateMAC(const cn_cbor *pControl)
{
	int cbEncoded = 0;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateMAC(pControl, pbEncoded, cbEncoded);
}

int BuildMacMessage(const cn_cbor *pControl)
{
	int iRecipient = 0;
	HCOSE_RECIPIENT hRecip = nullptr;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return 0;
	}

	HCOSE_MAC hMacObj =
		COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		if (hMacObj != nullptr) {
			COSE_Mac_Free(hMacObj);
		}
		if (hRecip != nullptr) {
			COSE_Recipient_Free(hRecip);
		}
		CFails += 1;
		return 1;
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

	if (!SetSendingAttributes((HCOSE)hMacObj, pMac, Attributes_MAC_protected)) {
		goto returnError;
	}

	const cn_cbor *pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pRecipients = pRecipients->first_child;
	for (iRecipient = 0; pRecipients != nullptr;
		 iRecipient++, pRecipients = pRecipients->next) {
		cn_cbor *pkey =
			BuildKey(cn_cbor_mapget_string(pRecipients, "key"), true);
		if (pkey == nullptr) {
			goto returnError;
		}

		hRecip = COSE_Recipient_Init(
			COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
		if (hRecip == nullptr) {
			goto returnError;
		}

		if (!SetSendingAttributes(
				(HCOSE)hRecip, pRecipients, Attributes_Recipient_protected)) {
			goto returnError;
		}

		if (!COSE_Recipient_SetKey(hRecip, pkey, nullptr)) {
			goto returnError;
		}

		cn_cbor *pSenderKey = cn_cbor_mapget_string(pRecipients, "sender_key");
		if (pSenderKey != nullptr) {
			cn_cbor *pSendKey = BuildKey(pSenderKey, false);
			if (!COSE_Recipient_SetSenderKey(hRecip, pSendKey, 2, nullptr)) {
				goto returnError;
			}
		}

		if (!COSE_Mac_AddRecipient(hMacObj, hRecip, nullptr)) {
			goto returnError;
		}

#if INCLUDE_COUNTERSIGNATURE
		// On the Recipient
		cn_cbor *countersigns1 =
			cn_cbor_mapget_string(pRecipients, "countersign");
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
					goto returnError;
				}

				if (!COSE_CounterSign_SetKey(
						hCountersign, pkeyCountersign, nullptr)) {
					goto returnError;
				}

				if (!COSE_Recipient_add_countersignature(
						hRecip, hCountersign, nullptr)) {
					goto returnError;
				}

				COSE_CounterSign_Free(hCountersign);
			}
		}

#endif

		COSE_Recipient_Free(hRecip);
		hRecip = nullptr;
	}

#if INCLUDE_COUNTERSIGNATURE
	// On the Evneloped body
	cn_cbor *countersigns1 = cn_cbor_mapget_string(pMac, "countersign");
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

			if (!COSE_Mac_add_countersignature(hMacObj, hCountersign, nullptr)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			COSE_CounterSign_Free(hCountersign);
		}
	}

#endif

	if (!COSE_Mac_encrypt(hMacObj, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode((HCOSE)hMacObj, nullptr, 0, 0) + 1;
	byte *rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hMacObj, rgb, 0, cb);

	COSE_Mac_Free(hMacObj);

	int f = _ValidateMAC(pControl, rgb, cb);

	free(rgb);
	return f;
}

int MacMessage()
{
	HCOSE_MAC hEncObj =
		COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
	const char *sz = "This is the content to be used";
	byte rgbSecret[256 / 8] = {'a', 'b', 'c'};
	byte rgbKid[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
	int cbKid = 6;
	size_t cb = 0;
	byte *rgb = nullptr;

	if (hEncObj == nullptr) {
		errorReturn:
		if (hEncObj != nullptr) {
			COSE_Mac_Free(hEncObj);
		}
		CFails++;
		return 0;
	}

	if (!COSE_Mac_map_put_int(hEncObj, COSE_Header_Algorithm,
			cn_cbor_int_create(
				COSE_Algorithm_HMAC_256_256, CBOR_CONTEXT_PARAM_COMMA nullptr),
			COSE_PROTECT_ONLY, nullptr)) {
		goto errorReturn;
	}
	if (!COSE_Mac_SetContent(hEncObj, (byte *)sz, strlen(sz), nullptr)) {
		goto errorReturn;
	}

	HCOSE_RECIPIENT hRecip = COSE_Recipient_from_shared_secret(rgbSecret,
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

	cb = COSE_Encode((HCOSE)hEncObj, nullptr, 0, 0);
	if (cb == 0) {
		goto errorReturn;
	}

	rgb = (byte *)malloc(cb);
	if (rgb == nullptr) {
		goto errorReturn;
	}
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);
	if (cb == 0) {
		goto errorReturn;
	}

	COSE_Mac_Free(hEncObj);

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

	int typ;
	hEncObj = (HCOSE_MAC)COSE_Decode(
		rgb, (int)cb, &typ, COSE_mac_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hEncObj == nullptr) {
		goto errorReturn;
	}

	int iRecipient = 0;
	do {
		HCOSE_RECIPIENT hRecip2;

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

		COSE_Recipient_Free(hRecip2);

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
	cn_cbor *pkey = nullptr;	
	HCOSE_MAC0 hMAC = nullptr;
	int type;
	bool fFail = false;
	bool fFailBody = false;
	bool fUnsuportedAlg = false;

	if (false) {
	exitHere:
		if (pkey != nullptr) {
			CN_CBOR_FREE(pkey, context);
		}
		if (hMAC != nullptr) {
			COSE_Mac0_Free(hMAC);
		}

		if (fFail) {
			CFails += 1;
		}
		return fUnsuportedAlg ? 0 : 1;

	errorReturn:
		if (hMAC != nullptr) {
			COSE_Mac0_Free(hMAC);
		}
		CFails += 1;
		return (fFail || fUnsuportedAlg) ? 0 : 1;
	}

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	hMAC = (HCOSE_MAC0)COSE_Decode(pbEncoded, cbEncoded, &type,
		COSE_mac0_object, CBOR_CONTEXT_PARAM_COMMA nullptr);
	if (hMAC == nullptr) {
		if (fFailBody) {
			return 0;
		}
		else {
			goto errorReturn;
		}
	}

	if ((pInput == nullptr) || (pInput->type != CN_CBOR_MAP)) {
		goto errorReturn;
	}
	pMac = cn_cbor_mapget_string(pInput, "mac0");
	if ((pMac == nullptr) || (pMac->type != CN_CBOR_MAP)) {
		goto errorReturn;
	}

	if (!SetReceivingAttributes((HCOSE)hMAC, pMac, Attributes_MAC0_protected)) {
		goto errorReturn;
	}

	pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto errorReturn;
	}

	pRecipients = pRecipients->first_child;

	pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"), true);
	if (pkey == nullptr) {
		fFail = true;
		goto exitHere;
	}

	cn_cbor *k = cn_cbor_mapget_int(pkey, -1);

	cn_cbor *alg =
		COSE_Mac0_map_get_int(hMAC, COSE_Header_Algorithm, COSE_BOTH, nullptr);
	if (!IsAlgorithmSupported(alg)) {
		fUnsuportedAlg = true;
	}

	pFail = cn_cbor_mapget_string(pRecipients, "fail");
	if (COSE_Mac0_validate(hMAC, k->v.bytes, k->length, nullptr)) {
		if (fUnsuportedAlg) {
			fFail = true;
			fUnsuportedAlg = false;
		}
		else if ((pFail != nullptr) && (pFail->type != CN_CBOR_TRUE)) {
			fFail = true;
		}
	}
	else {
		if ((pFail == nullptr) || (pFail->type == CN_CBOR_FALSE)) {
			fFail = true;
		}
		if (fUnsuportedAlg) {
			fFail = false;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	//  Countersign on Mac0 Body

	//  Validate counter signatures on signers
	cn_cbor *countersignList = cn_cbor_mapget_string(pMac, "countersign");
	if (countersignList != nullptr) {
		cn_cbor *countersigners =
			cn_cbor_mapget_string(countersignList, "signers");
		if (countersigners == nullptr) {
			fFail = true;
			goto exitHere;
		}
		int count = countersigners->length;
		bool forward = true;

		if (COSE_Mac0_map_get_int(hMAC, COSE_Header_CounterSign,
				COSE_UNPROTECT_ONLY, 0) == nullptr) {
			fFail = true;
			goto exitHere;
		}

		for (int counterNo = 0; counterNo < count; counterNo++) {
			bool noSignAlg = false;

			HCOSE_COUNTERSIGN h =
				COSE_Mac0_get_countersignature(hMAC, counterNo, 0);
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

			alg = COSE_CounterSign_map_get_int(
				h, COSE_Header_Algorithm, COSE_BOTH, nullptr);
			if (!IsAlgorithmSupported(alg)) {
				fUnsuportedAlg = true;
				noSignAlg = true;
			}

			if (COSE_Mac0_CounterSign_validate(hMAC, h, 0)) {
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

int ValidateMac0(const cn_cbor *pControl)
{
	int cbEncoded;
	byte *pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateMac0(pControl, pbEncoded, cbEncoded);
}

int BuildMac0Message(const cn_cbor *pControl)
{
	cn_cbor *pkey = nullptr;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor *pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != nullptr) && (pFail->type == CN_CBOR_TRUE)) {
		return 0;
	}

	HCOSE_MAC0 hMacObj =
		COSE_Mac0_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

	const cn_cbor *pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == nullptr) {
	returnError:
		if (pkey != nullptr) {
			CN_CBOR_FREE(pkey, context);
		}
		COSE_Mac0_Free(hMacObj);
		CFails += 1;
		return 1;
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

	if (!SetSendingAttributes(
			(HCOSE)hMacObj, pMac, Attributes_MAC0_protected)) {
		goto returnError;
	}

	const cn_cbor *pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == nullptr) || (pRecipients->type != CN_CBOR_ARRAY)) {
		goto returnError;
	}

	pRecipients = pRecipients->first_child;

	pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"), false);
	if (pkey == nullptr) {
		goto returnError;
	}

	cn_cbor *k = cn_cbor_mapget_int(pkey, -1);

#if INCLUDE_COUNTERSIGNATURE
	// On the sign body
	cn_cbor *countersigns = cn_cbor_mapget_string(pMac, "countersign");
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

			if (!COSE_Mac0_add_countersignature(hMacObj, hCountersign, nullptr)) {
				COSE_CounterSign_Free(hCountersign);
				goto returnError;
			}

			COSE_CounterSign_Free(hCountersign);
		}
	}

#endif

	if (!COSE_Mac0_encrypt(hMacObj, k->v.bytes, k->length, nullptr)) {
		goto returnError;
	}

	size_t cb = COSE_Encode((HCOSE)hMacObj, nullptr, 0, 0) + 1;
	byte *rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hMacObj, rgb, 0, cb);

	COSE_Mac0_Free(hMacObj);
	CN_CBOR_FREE(pkey, context);

	int f = _ValidateMac0(pControl, rgb, cb);

	free(rgb);
	return f;
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
	if (COSE_Mac_validate((HCOSE_MAC)hEncrypt, (HCOSE_RECIPIENT)hMAC, nullptr)) {
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
	hEncrypt =
		COSE_Encrypt_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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
	if (COSE_Mac_validate((HCOSE_MAC)hEncrypt, (HCOSE_RECIPIENT)hMAC, nullptr)) {
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

	hMAC = COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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

	hMAC = COSE_Mac_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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

	hEncrypt =
		COSE_Encrypt_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

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

	hEncrypt =
		COSE_Encrypt_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);

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

	hMAC = COSE_Mac0_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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

	hMAC = COSE_Mac0_Init(COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA nullptr);
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
