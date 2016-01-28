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


int _ValidateEnveloped(const cn_cbor * pControl, const byte * pbEncoded, size_t cbEncoded)
{
	const cn_cbor * pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor * pFail;
	const cn_cbor * pEnveloped;
	const cn_cbor * pRecipients;
	HCOSE_ENVELOPED hEnc;
	int type;
	int iRecipient;
	bool fFail = false;
	bool fFailBody = false;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == NULL) || (pInput->type != CN_CBOR_MAP)) goto errorReturn;
	pEnveloped = cn_cbor_mapget_string(pInput, "enveloped");
	if ((pEnveloped == NULL) || (pEnveloped->type != CN_CBOR_MAP)) goto errorReturn;

	pRecipients = cn_cbor_mapget_string(pEnveloped, "recipients");
	if ((pRecipients == NULL) || (pRecipients->type != CN_CBOR_ARRAY)) goto errorReturn;

	iRecipient = (int) pRecipients->length - 1;
	pRecipients = pRecipients->first_child;
	for (; pRecipients != NULL; iRecipient--, pRecipients = pRecipients->next) {

		hEnc = (HCOSE_ENVELOPED)COSE_Decode(pbEncoded, cbEncoded, &type, COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA NULL);
		if (hEnc == NULL) { if (fFailBody) return 0; else  goto errorReturn; }

		if (!SetReceivingAttributes((HCOSE)hEnc, pEnveloped, Attributes_Enveloped_protected)) goto errorReturn;

		cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"), false);
		if (pkey == NULL) {
			fFail = true;
			continue;
		}

		HCOSE_RECIPIENT hRecip = COSE_Enveloped_GetRecipient(hEnc, iRecipient, NULL);
		if (hRecip == NULL) {
			fFail = true;
			continue;
		}

		if (!COSE_Recipient_SetKey(hRecip, pkey, NULL)) {
			fFail = true;
			continue;
		}

		if (!SetReceivingAttributes((HCOSE) hRecip, pRecipients, Attributes_Recipient_protected)) goto errorReturn;

		pFail = cn_cbor_mapget_string(pRecipients, "fail");
		if (COSE_Enveloped_decrypt(hEnc, hRecip, NULL)) {
			if ((pFail != NULL) && (pFail->type != CN_CBOR_TRUE)) fFail = true;
		}
		else {
			if ((pFail == NULL) || (pFail->type == CN_CBOR_FALSE)) fFail = true;
		}

		COSE_Enveloped_Free(hEnc);
		COSE_Recipient_Free(hRecip);
	}

	if (fFailBody) {
		if (!fFail) fFail = true;
		else fFail = false;
	}

	if (fFail) CFails += 1;
	return 0;

errorReturn:
	CFails += 1;
	return 0;
}

int ValidateEnveloped(const cn_cbor * pControl)
{
	int cbEncoded;
	byte * pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateEnveloped(pControl, pbEncoded, cbEncoded);
}

int BuildEnvelopedMessage(const cn_cbor * pControl)
{
	int iRecipient;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor * pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) return 0;

	HCOSE_ENVELOPED hEncObj = COSE_Enveloped_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);

	const cn_cbor * pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == NULL) goto returnError;
	const cn_cbor * pEnveloped = cn_cbor_mapget_string(pInputs, "enveloped");
	if (pEnveloped == NULL) goto returnError;

	const cn_cbor * pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Enveloped_SetContent(hEncObj, pContent->v.bytes, pContent->length, NULL)) goto returnError;

	if (!SetSendingAttributes((HCOSE)hEncObj, pEnveloped, Attributes_Enveloped_protected)) goto returnError;

	const cn_cbor * pAlg = COSE_Enveloped_map_get_int(hEncObj, 1, COSE_BOTH, NULL);
	if (pAlg == NULL) goto returnError;

	const cn_cbor * pRecipients = cn_cbor_mapget_string(pEnveloped, "recipients");
	if ((pRecipients == NULL) || (pRecipients->type != CN_CBOR_ARRAY)) goto returnError;

	pRecipients = pRecipients->first_child;
	for (iRecipient = 0; pRecipients != NULL; iRecipient++, pRecipients = pRecipients->next) {
		cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"), true);
		if (pkey == NULL) goto returnError;

		HCOSE_RECIPIENT hRecip = COSE_Recipient_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
		if (hRecip == NULL) goto returnError;

		if (!SetSendingAttributes((HCOSE)hRecip, pRecipients, Attributes_Recipient_protected)) goto returnError;

		if (!COSE_Recipient_SetKey(hRecip, pkey, NULL)) goto returnError;

		if (!COSE_Enveloped_AddRecipient(hEncObj, hRecip, NULL)) goto returnError;

		COSE_Recipient_Free(hRecip);
	}

	if (!COSE_Enveloped_encrypt(hEncObj, NULL)) goto returnError;

	size_t cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0) + 1;
	byte * rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);

	COSE_Enveloped_Free(hEncObj);

	int f = _ValidateEnveloped(pControl, rgb, cb);
	free(rgb);
	return f;

returnError:
	CFails += 1;
	return 1;
}

int EncryptMessage()
{
	HCOSE_ENVELOPED hEncObj = COSE_Enveloped_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
	byte rgbSecret[128 / 8] = { 'a', 'b', 'c' };
	int cbSecret = 128/8;
	byte  rgbKid[15] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'l', 'm', 'n', 'o', 'p' };
	int cbKid = 6;
	size_t cb;
	byte * rgb;
	char * sz = "This is the content to be used";
	HCOSE_RECIPIENT hRecip = NULL;

	if (hEncObj == NULL) goto errorReturn;
	if (!COSE_Enveloped_map_put_int(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(COSE_Algorithm_AES_CCM_16_64_128, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_PROTECT_ONLY, NULL)) goto errorReturn;
	if (!COSE_Enveloped_SetContent(hEncObj, (byte *) sz, strlen(sz), NULL)) goto errorReturn;
	if (!COSE_Enveloped_map_put_int(hEncObj, COSE_Header_IV, cn_cbor_data_create(rgbKid, 13, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_UNPROTECT_ONLY, NULL)) goto errorReturn;

	hRecip = COSE_Recipient_from_shared_secret(rgbSecret, cbSecret, rgbKid, cbKid, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (hRecip == NULL) goto errorReturn;
	if (!COSE_Enveloped_AddRecipient(hEncObj, hRecip, NULL)) goto errorReturn;

	if (!COSE_Enveloped_encrypt(hEncObj, NULL)) goto errorReturn;

	cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0);
	if (cb < 1) goto errorReturn;
	rgb = (byte *)malloc(cb);
	if (rgb == NULL) goto errorReturn;
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);
	if (cb < 1) goto errorReturn;

	COSE_Recipient_Free(hRecip);
	hRecip = NULL;

	FILE * fp = fopen("test.cbor", "wb");
	fwrite(rgb, cb, 1, fp);
	fclose(fp);

#if 0
	char * szX;
	int cbPrint = 0;
	cn_cbor * cbor = COSE_get_cbor((HCOSE) hEncObj);
	cbPrint = cn_cbor_printer_write(NULL, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, "%s", szX);
	fprintf(stdout, "\r\n");
#endif

	COSE_Enveloped_Free(hEncObj);
	hEncObj = NULL;

	/* */

	int typ;
	hEncObj = (HCOSE_ENVELOPED) COSE_Decode(rgb, (int) cb, &typ, COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (hEncObj == NULL) goto errorReturn;
	
	int iRecipient = 0;
	do {
		hRecip = COSE_Enveloped_GetRecipient(hEncObj, iRecipient, NULL);
		if (hRecip == NULL) break;

		if (!COSE_Recipient_SetKey_secret(hRecip, rgbSecret, cbSecret, NULL, 0, NULL)) goto errorReturn;

		if (!COSE_Enveloped_decrypt(hEncObj, hRecip, NULL)) goto errorReturn;

		COSE_Recipient_Free(hRecip);
		hRecip = NULL;

		iRecipient += 1;

	} while (true);

	COSE_Enveloped_Free(hEncObj);
	return 1;

errorReturn:
	if (hEncObj != NULL) COSE_Enveloped_Free(hEncObj);
	if (hRecip != NULL) COSE_Recipient_Free(hRecip);
	CFails++;
	return 0;
}


/********************************************/

int _ValidateEncrypt(const cn_cbor * pControl, const byte * pbEncoded, size_t cbEncoded)
{
	const cn_cbor * pInput = cn_cbor_mapget_string(pControl, "input");
	const cn_cbor * pFail;
	const cn_cbor * pEncrypt;
	const cn_cbor * pRecipients;
	HCOSE_ENCRYPT hEnc;
	int type;
	bool fFail = false;
	bool fFailBody = false;

	pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) {
		fFailBody = true;
	}

	if ((pInput == NULL) || (pInput->type != CN_CBOR_MAP)) goto returnError;
	pEncrypt = cn_cbor_mapget_string(pInput, "encrypted");
	if ((pEncrypt == NULL) || (pEncrypt->type != CN_CBOR_MAP)) goto returnError;

	pRecipients = cn_cbor_mapget_string(pEncrypt, "recipients");
	if ((pRecipients == NULL) || (pRecipients->type != CN_CBOR_ARRAY)) goto returnError;

	pRecipients = pRecipients->first_child;

	hEnc = (HCOSE_ENCRYPT)COSE_Decode(pbEncoded, cbEncoded, &type, COSE_encrypt_object, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (hEnc == NULL) { if (fFailBody) return 0; else  goto returnError; }

	if (!SetReceivingAttributes((HCOSE)hEnc, pEncrypt, Attributes_Encrypt_protected)) goto returnError;

	cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"), true);
	if (pkey == NULL) goto returnError;

	cn_cbor * k = cn_cbor_mapget_int(pkey, -1);
	if (k == NULL) {
		fFail = true;
		goto exitHere;
	}

	pFail = cn_cbor_mapget_string(pRecipients, "fail");
	if (COSE_Encrypt_decrypt(hEnc, k->v.bytes, k->length, NULL)) {
		if ((pFail != NULL) && (pFail->type != CN_CBOR_TRUE)) fFail = true;
	}
	else {
		if ((pFail == NULL) || (pFail->type == CN_CBOR_FALSE)) fFail = true;
	}

	COSE_Encrypt_Free(hEnc);

exitHere:

	if (fFailBody) {
		if (!fFail) fFail = true;
		else fFail = false;
	}

	if (fFail) CFails += 1;
	return 0;

returnError:
	CFails += 1;
	return 0;
}

int ValidateEncrypt(const cn_cbor * pControl)
{
	int cbEncoded;
	byte * pbEncoded = GetCBOREncoding(pControl, &cbEncoded);

	return _ValidateEncrypt(pControl, pbEncoded, cbEncoded);
}

int BuildEncryptMessage(const cn_cbor * pControl)
{

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

	const cn_cbor * pFail = cn_cbor_mapget_string(pControl, "fail");
	if ((pFail != NULL) && (pFail->type == CN_CBOR_TRUE)) return 0;

	HCOSE_ENCRYPT hEncObj = COSE_Encrypt_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);

	const cn_cbor * pInputs = cn_cbor_mapget_string(pControl, "input");
	if (pInputs == NULL) goto returnError;
	const cn_cbor * pEncrypt = cn_cbor_mapget_string(pInputs, "encrypted");
	if (pEncrypt == NULL) goto returnError;

	const cn_cbor * pContent = cn_cbor_mapget_string(pInputs, "plaintext");
	if (!COSE_Encrypt_SetContent(hEncObj, pContent->v.bytes, pContent->length, NULL)) goto returnError;

	if (!SetSendingAttributes((HCOSE)hEncObj, pEncrypt, Attributes_Encrypt_protected)) goto returnError;

	const cn_cbor * pAlg = COSE_Encrypt_map_get_int(hEncObj, 1, COSE_BOTH, NULL);
	if (pAlg == NULL) goto returnError;

	const cn_cbor * pRecipients = cn_cbor_mapget_string(pEncrypt, "recipients");
	if ((pRecipients == NULL) || (pRecipients->type != CN_CBOR_ARRAY)) goto returnError;

	pRecipients = pRecipients->first_child;
		cn_cbor * pkey = BuildKey(cn_cbor_mapget_string(pRecipients, "key"), false);
		if (pkey == NULL) goto returnError;

		cn_cbor * k = cn_cbor_mapget_int(pkey, -1);


	if (!COSE_Encrypt_encrypt(hEncObj, k->v.bytes, k->length, NULL)) goto returnError;

	size_t cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0) + 1;
	byte * rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);

	COSE_Encrypt_Free(hEncObj);

	int f = _ValidateEncrypt(pControl, rgb, cb);
	free(rgb);
	return f;

returnError:
	CFails += 1;
	return 1;
}

void Enveloped_Corners()
{
	HCOSE_ENVELOPED hEncryptNULL = NULL;
	HCOSE_ENVELOPED hEncrypt = NULL;
	HCOSE_ENVELOPED hEncryptBad = NULL;
	HCOSE_RECIPIENT hRecipientNULL = NULL;
	HCOSE_RECIPIENT hRecipient = NULL;
	HCOSE_RECIPIENT hRecipientBad = NULL;
	byte rgb[10];
	cn_cbor * cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA NULL);
	cose_errback cose_error;

        hEncrypt = COSE_Enveloped_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
        hEncryptBad = (HCOSE_ENVELOPED) COSE_Mac_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
        hRecipient = COSE_Recipient_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
        hRecipientBad = (HCOSE_RECIPIENT) COSE_Mac_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);

	//  Missing case - addref then release on item


        //
        //  Do parameter checks
        //      - NULL handle
        //      - Incorrect handle
        //      - NULL pointer
        //

        CHECK_FAILURE(COSE_Enveloped_SetContent(hEncryptNULL, rgb, 10, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_SetContent(hEncryptBad, rgb, 10, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_SetContent(hEncrypt, NULL, 10, &cose_error), COSE_ERR_INVALID_PARAMETER, CFails++);


	CHECK_FAILURE(COSE_Enveloped_map_put_int(hEncryptNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_map_put_int(hEncryptBad, 1, cn, COSE_PROTECT_ONLY, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_map_put_int(hEncrypt, 1, cn, COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error), COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Enveloped_map_put_int(hEncrypt, 1, NULL, COSE_PROTECT_ONLY, &cose_error), COSE_ERR_INVALID_PARAMETER, CFails++);
        

        CHECK_FAILURE(COSE_Enveloped_map_get_int(hEncryptNULL, 1, COSE_BOTH, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_map_get_int(hEncryptBad, 1, COSE_BOTH, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);


        CHECK_FAILURE(COSE_Enveloped_encrypt(hEncryptNULL, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_encrypt(hEncryptBad, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);

        CHECK_FAILURE(COSE_Enveloped_decrypt(hEncryptNULL, hRecipient, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_decrypt(hEncryptBad, hRecipient, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_decrypt(hEncrypt, hRecipientNULL, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        CHECK_FAILURE(COSE_Enveloped_decrypt(hEncrypt, hRecipientBad, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);


	CHECK_FAILURE(COSE_Enveloped_AddRecipient(hEncryptNULL, hRecipient, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_AddRecipient(hEncryptBad, hRecipient, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_AddRecipient(hEncrypt, hRecipientNULL, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_AddRecipient(hEncrypt, hRecipientBad, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
        
	CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncryptNULL, 0, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncryptBad, 0, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
            
	CHECK_FAILURE(COSE_Enveloped_SetExternal(hEncryptNULL, rgb, 10, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_SetExternal(hEncryptBad, rgb, 10, &cose_error), COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_SetExternal(hEncrypt, NULL, 10, &cose_error), COSE_ERR_INVALID_PARAMETER, CFails++);
            
	if (!COSE_Enveloped_Free(hEncrypt)) CFails++;
	if (!COSE_Recipient_Free(hRecipient)) CFails++;


	//
	//  Unsupported algorithm

	hEncrypt = COSE_Enveloped_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (hEncrypt == NULL) CFails++;
	CHECK_RETURN(COSE_Enveloped_SetContent(hEncrypt, (byte *) "Message", 7, &cose_error), COSE_ERR_NONE, CFails++);
	CHECK_RETURN(COSE_Enveloped_map_put_int(hEncrypt, COSE_Header_Algorithm, cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_PROTECT_ONLY, &cose_error), COSE_ERR_NONE, CFails++);
	hRecipient = COSE_Recipient_from_shared_secret(rgb, sizeof(rgb), rgb, sizeof(rgb), CBOR_CONTEXT_PARAM_COMMA NULL);
	if (hRecipient == NULL) CFails++;
	CHECK_RETURN(COSE_Enveloped_AddRecipient(hEncrypt, hRecipient, &cose_error), COSE_ERR_NONE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEncrypt, &cose_error), COSE_ERR_UNKNOWN_ALGORITHM, CFails++);

	CHECK_RETURN(COSE_Enveloped_map_put_int(hEncrypt, COSE_Header_Algorithm, cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA NULL), COSE_PROTECT_ONLY, &cose_error), COE_ERR_NONE, CFails++);
	CHECK_FAILURE(COSE_Enveloped_encrypt(hEncrypt, &cose_error), COSE_ERR_UNKNOWN_ALGORITHM, CFails++);

        //
        //  Over shoot the recipients
        
        CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncrypt, -1, &cose_error), COSE_ERR_INVALID_PARAMETER, CFails++);
        CHECK_FAILURE_PTR(COSE_Enveloped_GetRecipient(hEncrypt, 9, &cose_error), COSE_ERR_INVALID_PARAMETER, CFails++);

	return;
}

void Encrypt_Corners()
{
	HCOSE_ENCRYPT hEncrypt = NULL;
	byte rgb[10];
	cn_cbor * cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA NULL);

	//  Missing case - addref then release on item

	//  NULL Handle checks

	if (COSE_Encrypt_SetContent(hEncrypt, rgb, 10, NULL)) CFails++;
	if (COSE_Encrypt_map_get_int(hEncrypt, 1, COSE_BOTH, NULL)) CFails++;
	if (COSE_Encrypt_map_put_int(hEncrypt, 1, cn, COSE_PROTECT_ONLY, NULL)) CFails++;
	if (COSE_Encrypt_SetExternal(hEncrypt, rgb, 10, NULL)) CFails++;
	if (COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), NULL)) CFails++;
	if (COSE_Encrypt_decrypt(hEncrypt, rgb, sizeof(rgb), NULL)) CFails++;
	if (COSE_Encrypt_Free((HCOSE_ENCRYPT)hEncrypt)) CFails++;

	//  Wrong type of handle checks

	hEncrypt = (HCOSE_ENCRYPT) COSE_Mac_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);

	if (COSE_Encrypt_SetContent(hEncrypt, rgb, 10, NULL)) CFails++;
	if (COSE_Encrypt_map_get_int(hEncrypt, 1, COSE_BOTH, NULL)) CFails++;
	if (COSE_Encrypt_map_put_int(hEncrypt, 1, cn, COSE_PROTECT_ONLY, NULL)) CFails++;
	if (COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), NULL)) CFails++;
	if (COSE_Encrypt_SetExternal(hEncrypt, rgb, 10, NULL)) CFails++;
	if (COSE_Encrypt_decrypt(hEncrypt, rgb, sizeof(rgb), NULL)) CFails++;
	if (COSE_Encrypt_Free(hEncrypt)) CFails++;

	//
	//  Unsupported algorithm

	hEncrypt = COSE_Encrypt_Init(0, CBOR_CONTEXT_PARAM_COMMA NULL);
	if (hEncrypt == NULL) CFails++;
	if (!COSE_Encrypt_SetContent(hEncrypt, (byte *) "Message", 7, NULL)) CFails++;
	if (!COSE_Encrypt_map_put_int(hEncrypt, COSE_Header_Algorithm, cn_cbor_int_create(-99, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_PROTECT_ONLY, NULL)) CFails++;
	if (COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), NULL)) CFails++;

	if (!COSE_Encrypt_map_put_int(hEncrypt, COSE_Header_Algorithm, cn_cbor_string_create("hmac", CBOR_CONTEXT_PARAM_COMMA NULL), COSE_PROTECT_ONLY, NULL)) CFails++;
	if (COSE_Encrypt_encrypt(hEncrypt, rgb, sizeof(rgb), NULL)) CFails++;

	return;
}
