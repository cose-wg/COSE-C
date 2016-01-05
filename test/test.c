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


struct {
	char * sz;
	int    i;
} RgAlgorithmNames[15] = {
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
	{"A256GCM", COSE_Algorithm_AES_GCM_256}
};

int MapAlgorithmName(const cn_cbor * p)
{
	unsigned int i;

	for (i = 0; i < _countof(RgAlgorithmNames); i++) {
		if (strcmp(RgAlgorithmNames[i].sz, p->v.str) == 0) return RgAlgorithmNames[i].i;
	}

	assert(false);

	return 0;
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

struct {
	char * szKey;
	int kty;
	int operation;
	int keyNew;
} RgStringKeys[7] = {
	{ "kty", 0, OPERATION_IGNORE, 0},
	{ "kid", 0, OPERATION_NONE, 1},
	{ "crv", 2, OPERATION_NONE, -1},
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
					}
					i = 99;
				}
			}
		}
	}

	return pKeyOut;
}

int ValidateMAC(const cn_cbor * pControl)
{
	int cbEncoded;
	byte * pbEncoded = GetCBOREncoding(pControl, &cbEncoded);
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

	pRecipients = pRecipients->first_child;
	for (iRecipient = 0; pRecipients != NULL; iRecipient++,pRecipients=pRecipients->next) {
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

	return 0;

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

int SignMessage()
{
	HCOSE_SIGN hEncObj = COSE_Sign_Init(CBOR_CONTEXT_PARAM_COMMA NULL);
	char * sz = "This is the content to be used";
	size_t cb;
	byte * rgb;

			byte rgbX[] = { 0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba, 0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a, 0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d, 0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d };
		byte rgbY[] = { 0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7, 0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d, 0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c, 0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c };
		byte kid[] = { 0x6d, 0x65, 0x72, 0x69, 0x61, 0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x79, 0x62, 0x75, 0x63, 0x6, 0xb4, 0x06, 0x27, 0x56, 0x36, 0xb6, 0xc6, 0x16, 0xe6, 0x42, 0xe6, 0x57, 0x86, 0x16, 0xd7, 0x06, 0x65};
		byte rgbD[] = {0xaf, 0xf9, 0x07, 0xc9, 0x9f, 0x9a, 0xd3, 0xaa, 0xe6, 0xc4, 0xcd, 0xf2, 0x11, 0x22, 0xbc, 0xe2, 0xbd, 0x68, 0xb5, 0x28, 0x3e, 0x69, 0x07, 0x15, 0x4a, 0xd9, 0x11, 0x84, 0x0f, 0xa2, 0x08, 0xcf};
			
			cn_cbor * pkey = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_mapput_int(pkey, COSE_Key_Type, cn_cbor_int_create(COSE_Key_Type_EC2, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_mapput_int(pkey, -1, cn_cbor_int_create(1, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_mapput_int(pkey, -2, cn_cbor_data_create(rgbX, sizeof(rgbX), CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_mapput_int(pkey, -3, cn_cbor_data_create(rgbY, sizeof(rgbY), CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_mapput_int(pkey, COSE_Key_ID, cn_cbor_data_create(kid, sizeof(kid), CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);
	cn_cbor_mapput_int(pkey, -4, cn_cbor_data_create(rgbD, sizeof(rgbD), CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);

	COSE_Sign_SetContent(hEncObj, (byte *) sz, strlen(sz), NULL);
	COSE_Sign_add_signer(hEncObj, pkey, COSE_Algorithm_ECDSA_SHA_256, NULL);

	COSE_Sign_Sign(hEncObj, NULL);

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

	COSE_Sign_Free(hEncObj);

	/* */

	int typ;
	hEncObj = (HCOSE_SIGN)COSE_Decode(rgb, (int)cb, &typ, COSE_sign_object, NULL, NULL);

#if 0
	int iRecipient = 0;
	do {
		HCOSE_RECIPIENT hRecip;

		hRecip = COSE_Encrypt_GetRecipient(hEncObj, iRecipient, NULL);
		if (hRecip == NULL) break;

		COSE_Recipient_SetKey(hRecip, rgbSecret, cbSecret, NULL);

		COSE_Encrypt_decrypt(hEncObj, hRecip, NULL);

		iRecipient += 1;

	} while (true);
#endif

	COSE_Sign_Free(hEncObj);

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
