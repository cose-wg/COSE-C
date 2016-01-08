// test.c : Defines the entry point for the console application.
//

#define _CRT_SECURE_NO_WARNINGS
#define USE_CBOR_CONTEXT 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose.h>
#include <cn-cbor/cn-cbor.h>
#include <assert.h>

#include "json.h"

#include "test.h"


extern int EncryptMessage();
int CFails = 0;


typedef struct _NameMap {
	char * sz;
	int    i;
} NameMap;

NameMap RgAlgorithmNames[23] = {
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
	{"AES-CCM-64-256/128", COSE_Algorithm_AES_CCM_64_128_256}
};


NameMap RgCurveNames[3] = {
	{"P-256", 1},
	{"P-384", 2},
	{"P-521", 3}
};

int MapName(const cn_cbor * p, NameMap * rgMap, unsigned int cMap)
{
	unsigned int i;

	for (i = 0; i < cMap; i++) {
		if (strcmp(rgMap[i].sz, p->v.str) == 0) return rgMap[i].i;
	}

	assert(false);

	return 0;
}

int MapAlgorithmName(const cn_cbor * p)
{
	return MapName(p, RgAlgorithmNames, _countof(RgAlgorithmNames));
}

cn_cbor * cn_cbor_clone(const cn_cbor * pIn)
{
	cn_cbor * pOut = NULL;
	char * sz;

	switch (pIn->type) {
	case CN_CBOR_TEXT:
		sz = malloc(pIn->length + 1);
		memcpy(sz, pIn->v.str, pIn->length);
		sz[pIn->length] = 0;
		pOut = cn_cbor_string_create(sz, CBOR_CONTEXT_PARAM_COMMA NULL);
		break;

	default:
		break;
	}

	return pOut;
}

byte fromHex(char c)
{
	if (('0' <= c) && (c <= '9')) return c - '0';
	if (('A' <= c) && (c <= 'F')) return c - 'A' + 10;
	fprintf(stderr, "Invalid hex");
	exit(1);
}

byte * GetCBOREncoding(const cn_cbor * pControl, int * pcbEncoded)
{
	const cn_cbor * pOutputs = cn_cbor_mapget_string(pControl, "output");
	const cn_cbor * pCBOR;
	byte * pb = NULL;
	const byte * pb2;
	int i;

	if ((pOutputs == NULL) || (pOutputs->type != CN_CBOR_MAP)) {
		fprintf(stderr, "Invalid output\n");
		exit(1);
	}

	pCBOR = cn_cbor_mapget_string(pOutputs, "cbor");
	if ((pCBOR == NULL) || (pCBOR->type != CN_CBOR_TEXT)) {
		fprintf(stderr, "Invalid cbor object");
		exit(1);
	}

	pb = malloc(pCBOR->length / 2);
	pb2 = pCBOR->v.bytes;

	for (i = 0; i < pCBOR->length; i += 2) {
		pb[i / 2] = fromHex(pb2[i]) * 16 + fromHex(pb2[i + 1]);
	}

	*pcbEncoded = (int) (pCBOR->length / 2);
	return pb;
}

#define OPERATION_NONE 0
#define OPERATION_BASE64 1
#define OPERATION_IGNORE 2
#define OPERATION_STRING 3

struct {
	char * szKey;
	int kty;
	int operation;
	int keyNew;
} RgStringKeys[7] = {
	{ "kty", 0, OPERATION_IGNORE, 0},
	{ "kid", 0, OPERATION_NONE, 1},
	{ "crv", 2, OPERATION_STRING, -1},
	{ "x", 2, OPERATION_BASE64, -2},
	{ "y", 2, OPERATION_BASE64, -3},
	{ "d", 2, OPERATION_BASE64, -4},
	{ "k", 4, OPERATION_BASE64, -1}
};

bool SetAttributes(HCOSE hHandle, const cn_cbor * pAttributes, int which)
{
	const cn_cbor * pKey;
	const cn_cbor * pValue;
	int keyNew;
	cn_cbor * pValueNew;

	if (pAttributes == NULL) return true;
	if (pAttributes->type != CN_CBOR_MAP) return false;

	for (pKey = pAttributes->first_child; pKey != NULL; pKey = pKey->next->next) {
		pValue = pKey->next;

		if (pKey->type != CN_CBOR_TEXT) return false;

		if (strcmp(pKey->v.str, "alg") == 0) {
			keyNew = COSE_Header_Algorithm;
			pValueNew = cn_cbor_int_create(MapAlgorithmName(pValue), CBOR_CONTEXT_PARAM_COMMA NULL);
		}
		else {
			continue;
		}

		switch (which) {
		case Attributes_MAC_protected:
			COSE_Mac_map_put((HCOSE_MAC)hHandle, keyNew, pValueNew, COSE_PROTECT_ONLY, NULL);
			break;

		case Attributes_MAC_unprotected:
			COSE_Mac_map_put((HCOSE_MAC)hHandle, keyNew, pValueNew, COSE_UNPROTECT_ONLY, NULL);
			break;

		case Attributes_Recipient_protected:
			COSE_Recipient_map_put((HCOSE_RECIPIENT)hHandle, keyNew, pValueNew, COSE_PROTECT_ONLY, NULL);
			break;

		case Attributes_Recipient_unprotected:
			COSE_Recipient_map_put((HCOSE_RECIPIENT)hHandle, keyNew, pValueNew, COSE_UNPROTECT_ONLY, NULL);
			break;

		case Attributes_Recipient_unsent:
			COSE_Recipient_map_put((HCOSE_RECIPIENT)hHandle, keyNew, pValueNew, COSE_DONT_SEND, NULL);
			break;

		case Attributes_Enveloped_protected:
			COSE_Encrypt_map_put((HCOSE_ENCRYPT)hHandle, keyNew, pValueNew, COSE_PROTECT_ONLY, NULL);
			break;

		case Attributes_Enveloped_unprotected:
			COSE_Encrypt_map_put((HCOSE_ENCRYPT)hHandle, keyNew, pValueNew, COSE_UNPROTECT_ONLY, NULL);
			break;

		case Attributes_Enveloped_unsent:
			COSE_Encrypt_map_put((HCOSE_ENCRYPT)hHandle, keyNew, pValueNew, COSE_DONT_SEND, NULL);
			break;
		}
	}

	return true;
}

cn_cbor * BuildKey(const cn_cbor * pKeyIn)
{
	cn_cbor * pKeyOut = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor * pKty = cn_cbor_mapget_string(pKeyIn, "kty");
	cn_cbor * p;
	cn_cbor * pKey;
	cn_cbor * pValue;
	int i;
	int kty;
	unsigned char * pb;
	size_t cb;

	if ((pKty == NULL) || (pKty->type != CN_CBOR_TEXT)) return NULL;
	if (pKty->length == 2) {
		if (strncmp(pKty->v.str, "EC", 2) == 0) kty = 2;
		else return NULL;
	}
	else if (pKty->length == 3) {
		if (strncmp(pKty->v.str, "oct", 3) == 0) kty = 4;
		else return NULL;
	}
	else return NULL;

	p = cn_cbor_int_create(kty, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (p == NULL) return NULL;
	if (!cn_cbor_mapput_int(pKeyOut, 1, p, CBOR_CONTEXT_PARAM_COMMA NULL)) return NULL;

	for (pKey = pKeyIn->first_child; pKey != NULL; pKey = pKey->next->next) {
		pValue = pKey->next;

		if (pKey->type == CN_CBOR_TEXT) {
			for (i = 0; i < 7; i++) {
				if ((pKey->length == strlen(RgStringKeys[i].szKey)) &&
					(strncmp(pKey->v.str, RgStringKeys[i].szKey, strlen(RgStringKeys[i].szKey)) == 0) &&
					((RgStringKeys[i].kty == 0) || (RgStringKeys[i].kty == kty))) {
					switch (RgStringKeys[i].operation) {
					case OPERATION_NONE:
						cn_cbor_mapput_int(pKeyOut, RgStringKeys[i].keyNew, cn_cbor_clone(pValue), CBOR_CONTEXT_PARAM_COMMA NULL);
						break;

					case OPERATION_BASE64:
						pb = base64_decode(pValue->v.str, pValue->length, &cb);
						cn_cbor_mapput_int(pKeyOut, RgStringKeys[i].keyNew, cn_cbor_data_create(pb, (int) cb, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
						break;

					case OPERATION_STRING:
						cn_cbor_mapput_int(pKeyOut, RgStringKeys[i].keyNew, cn_cbor_int_create(MapName(pValue, RgCurveNames, _countof(RgCurveNames)), CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
						break;
					}
					i = 99;
				}
			}
		}
	}

	return pKeyOut;
}

int _ValidateMAC(const cn_cbor * pControl, const byte * pbEncoded, size_t cbEncoded)
{
	const cn_cbor * pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor * pFail;
	const cn_cbor * pMac;
	const cn_cbor * pRecipients;
	HCOSE_MAC hMAC;
	int type;
	int iRecipient;
	bool fFail = false;
	bool fFailBody = false;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	hMAC = (HCOSE_MAC) COSE_Decode(pbEncoded, cbEncoded, &type, COSE_mac_object, NULL, NULL);
	if (hMAC == NULL) exit(1);

	if ((pInput == NULL) || (pInput->type != CN_CBOR_MAP)) exit(1);
	pMac = cn_cbor_mapget_string(pInput, "mac");
	if ((pMac == NULL) || (pMac->type != CN_CBOR_MAP)) exit(1);

	pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == NULL) || (pRecipients->type != CN_CBOR_ARRAY)) exit(1);

	iRecipient = (int) pRecipients->length - 1;
	pRecipients = pRecipients->first_child;
	for (; pRecipients != NULL; iRecipient--, pRecipients=pRecipients->next) {
		cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"));
		if (pkey == NULL) {
			fFail = true;
			continue;
		}

		HCOSE_RECIPIENT hRecip = COSE_Mac_GetRecipient(hMAC, iRecipient, NULL);
		if (hRecip == NULL) {
			fFail = true;
			continue;
		}

		if (!COSE_Recipient_SetKey(hRecip, pkey, NULL)) {
			fFail = true;
			continue;
		}

		pFail = cn_cbor_mapget_string(pRecipients, "fail");
		if (COSE_Mac_validate(hMAC, hRecip, NULL)) {
			if ((pFail != NULL) && (pFail->type != CN_CBOR_TRUE)) fFail = true;
		}
		else {
			if ((pFail == NULL) || (pFail->type == CN_CBOR_FALSE)) fFail = true;
		}
	}

	if (fFailBody) {
		if (!fFail) fFail = true;
		else fFail = false;
	}

	if (fFail) CFails += 1;
	return 0;
}

int ValidateMAC(const cn_cbor * pControl)
{
	int cbEncoded;
	byte * pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateMAC(pControl, pbEncoded, cbEncoded);
}

int BuildMacMessage(const cn_cbor * pControl)
{
	int iRecipient;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor * pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) return 0;

	HCOSE_MAC hMacObj = COSE_Mac_Init(CBOR_CONTEXT_PARAM_COMMA NULL);

	const cn_cbor * pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == NULL) exit(1);
	const cn_cbor * pMac = cn_cbor_mapget_string(pInputs, "mac");
	if (pMac == NULL) exit(1);

	const cn_cbor * pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Mac_SetContent(hMacObj, pContent->v.bytes, pContent->length, NULL)) goto returnError;

	if (!SetAttributes((HCOSE) hMacObj, cn_cbor_mapget_string(pMac, "protected"), Attributes_MAC_protected)) goto returnError;
	if (!SetAttributes((HCOSE) hMacObj, cn_cbor_mapget_string(pMac, "unprotected"), Attributes_MAC_unprotected)) goto returnError;

	const cn_cbor * pAlg = COSE_Mac_map_get_int(hMacObj, 1, COSE_BOTH, NULL);

	const cn_cbor * pRecipients = cn_cbor_mapget_string(pMac, "recipients");
	if ((pRecipients == NULL) || (pRecipients->type != CN_CBOR_ARRAY)) exit(1);

	pRecipients = pRecipients->first_child;
	for (iRecipient = 0; pRecipients != NULL; iRecipient++, pRecipients = pRecipients->next) {
		cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"));
		if (pkey == NULL) exit(1);

		HCOSE_RECIPIENT hRecip = COSE_Recipient_Init(CBOR_CONTEXT_PARAM_COMMA NULL);
		if (hRecip == NULL) exit(1);

		if (!SetAttributes((HCOSE) hRecip, cn_cbor_mapget_string(pRecipients, "protected"), Attributes_Recipient_protected)) goto returnError;
		if (!SetAttributes((HCOSE) hRecip, cn_cbor_mapget_string(pRecipients, "unprotected"), Attributes_Recipient_unprotected)) goto returnError;

		if (!COSE_Recipient_SetKey(hRecip, pkey, NULL)) exit(1);

		if (!COSE_Mac_AddRecipient(hMacObj, hRecip, NULL)) exit(1);
	}

	if (!COSE_Mac_encrypt(hMacObj, NULL)) exit(1);

	size_t cb = COSE_Encode((HCOSE)hMacObj, NULL, 0, 0) + 1;
	byte * rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hMacObj, rgb, 0, cb);

	int f = _ValidateMAC(pControl, rgb, cb);

	free(rgb);
	return f;

returnError:
	CFails += 1;
	return 1;
}

int MacMessage()
{
	HCOSE_MAC hEncObj = COSE_Mac_Init(CBOR_CONTEXT_PARAM_COMMA NULL);
	char * sz = "This is the content to be used";
	byte rgbSecret[256 / 8] = { 'a', 'b', 'c' };
	byte  rgbKid[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };
	int cbKid = 6;
	size_t cb;
	byte * rgb;

	COSE_Mac_map_put(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(COSE_Algorithm_HMAC_256_256, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_PROTECT_ONLY, NULL);
	COSE_Mac_SetContent(hEncObj, (byte *) sz, strlen(sz), NULL);

	COSE_Mac_add_shared_secret(hEncObj, COSE_Algorithm_Direct, rgbSecret, sizeof(rgbSecret), rgbKid, cbKid, NULL);

	COSE_Mac_encrypt(hEncObj, NULL);

	cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0) + 1;
	rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);


	FILE * fp = fopen("test.mac.cbor", "wb");
	fwrite(rgb, cb, 1, fp);
	fclose(fp);

#if 0
	char * szX;
	int cbPrint = 0;
	cn_cbor * cbor = COSE_get_cbor((HCOSE)hEncObj);
	cbPrint = cn_cbor_printer_write(NULL, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, "%s", szX);
	fprintf(stdout, "\r\n");
#endif

	COSE_Mac_Free(hEncObj);

	/* */

	int typ;
	hEncObj = (HCOSE_MAC) COSE_Decode(rgb,  (int) cb, &typ, COSE_mac_object, NULL, NULL);

	int iRecipient = 0;
	do {
		HCOSE_RECIPIENT hRecip;

		hRecip = COSE_Mac_GetRecipient(hEncObj, iRecipient, NULL);
		if (hRecip == NULL) break;

		COSE_Recipient_SetKey_secret(hRecip, rgbSecret, sizeof(rgbSecret), NULL);

		COSE_Mac_validate(hEncObj, hRecip, NULL);

		iRecipient += 1;

	} while (true);

	return 1;
}


bool cn_cbor_array_replace(cn_cbor * cb_array, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback *errp);

bool Test_cn_cbor_array_replace()
{
	cn_cbor * pRoot;
	cn_cbor * pItem;

	//  Cases that are not currently covered
	//  1.  Pass in invalid arguements

	cn_cbor_array_replace(NULL, NULL, 0, CBOR_CONTEXT_PARAM_COMMA NULL);

	//  2.  Insert 0 item with no items currently in the list
	pRoot = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	pItem = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_array_replace(pRoot, pItem, 0, CBOR_CONTEXT_PARAM_COMMA NULL);

	//  3. Insert 0 item w/ exactly one item in the list
	pItem = cn_cbor_int_create(6, CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_array_replace(pRoot, pItem, 0, CBOR_CONTEXT_PARAM_COMMA NULL);

	//  4.  The last item in the array
	pItem = cn_cbor_int_create(7, CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_array_replace(pRoot, pItem, 1, CBOR_CONTEXT_PARAM_COMMA NULL);

	return true;
}


int main(int argc, char ** argv)
{
	int i;
	const cn_cbor * pControl = NULL;

	for (i = 1; i < argc; i++) {
		if (argv[0][0] == '-') {

		}
		else {
			pControl = ParseJson(argv[i]);
		}
	}

	//
	//  If we are given a file name, then process the file name
	//

	if (pControl != NULL) {
		//  To find out what we are doing we need to get the correct item

		const cn_cbor * pInput = cn_cbor_mapget_string(pControl, "input");

		if ((pInput == NULL) || (pInput->type != CN_CBOR_MAP)) {
			fprintf(stderr, "No or bad input section");
			exit(1);
		}

		if (cn_cbor_mapget_string(pInput, "mac") != NULL) {
			ValidateMAC(pControl);
			BuildMacMessage(pControl);
		}
		else if (cn_cbor_mapget_string(pInput, "enveloped") != NULL) {
			ValidateEnveloped(pControl);
			BuildEncryptMessage(pControl);
		}
		else if (cn_cbor_mapget_string(pInput, "sign") != NULL) {
			ValidateSigned(pControl);
		}
	}
	else {
		MacMessage();
		SignMessage();
		EncryptMessage();
	}

	Test_cn_cbor_array_replace();

	if (CFails > 0) fprintf(stderr, "Failed %d tests\n", CFails);
	else fprintf(stderr, "SUCCESS\n");

	exit(CFails);
}
