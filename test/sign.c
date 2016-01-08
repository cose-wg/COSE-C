//  encrypt.c

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose.h>
#include <cn-cbor/cn-cbor.h>

#include "json.h"
#include "test.h"
#include "context.h"

int _ValidateSigned(const cn_cbor * pControl, const byte * pbEncoded, int cbEncoded)
{
	const cn_cbor * pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor * pFail;
	const cn_cbor * pSign;
	const cn_cbor * pSigners;
	HCOSE_SIGN	hSig;
	int type;
	int iSigner;
	bool fFail = false;
	bool fFailBody = false;

#ifdef USE_CBOR_CONTEXT
        allocator = CreateContext();
#endif 

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == NULL) || (pInput->type != CN_CBOR_MAP)) exit(1);
	pSign = cn_cbor_mapget_string(pInput, "sign");
	if ((pSign == NULL) || (pSign->type != CN_CBOR_MAP)) exit(1);

	pSigners = cn_cbor_mapget_string(pSign, "signers");
	if ((pSigners == NULL) || (pSigners->type != CN_CBOR_ARRAY)) exit(1);

	pSigners = pSigners->first_child;
	for (iSigner = 0; pSigners != NULL; iSigner++, pSigners = pSigners->next) {

		hSig = (HCOSE_SIGN)COSE_Decode(pbEncoded, cbEncoded, &type, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA NULL);
		if (hSig == NULL) exit(1);


		cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pSigners, "key"));
		if (pkey == NULL) {
			fFail = true;
			continue;
		}

		HCOSE_SIGNER hSigner = COSE_Sign_GetSigner(hSig, iSigner, NULL);
		if (hSigner == NULL) {
			fFail = true;
			continue;
		}

		if (!COSE_Signer_SetKey(hSigner, pkey, NULL)) {
			fFail = true;
			continue;
		}

		pFail = cn_cbor_mapget_string(pSigners, "fail");
		if (COSE_Sign_validate(hSig, hSigner, NULL)) {
			if ((pFail != NULL) && (pFail->type != CN_CBOR_TRUE)) fFail = true;
		}
		else {
			if ((pFail == NULL) || (pFail->type == CN_CBOR_FALSE)) fFail = true;
		}

		// COSE_Encrypt_Free(hSig);
	}

	if (fFailBody) {
		if (!fFail) fFail = true;
		else fFail = false;
	}

#ifdef USE_CBOR_CONTEXT
        FreeContext(allocator);
        allocator = NULL;
#endif

	if (fFail) CFails += 1;
	return 0;
}

int ValidateSigned(const cn_cbor * pControl)
{
	int cbEncoded;
	byte * pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateSigned(pControl, pbEncoded, cbEncoded);
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
	int iSigner = 0;
	do {
		HCOSE_RECIPIENT hSigner;

		hSigner = COSE_Encrypt_GetRecipient(hEncObj, iSigner, NULL);
		if (hSigner == NULL) break;

		COSE_Recipient_SetKey(hSigner, rgbSecret, cbSecret, NULL);

		COSE_Encrypt_decrypt(hEncObj, hSigner, NULL);

		iSigner += 1;

	} while (true);
#endif

	COSE_Sign_Free(hEncObj);

	return 1;
}
