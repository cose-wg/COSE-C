// test.cpp : Defines the entry point for the console application.
//

#define _CRT_SECURE_NO_WARNINGS
#define USE_CBOR_CONTEXT 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose.h>
#include <cn-cbor/cn-cbor.h>

extern int EncryptMessage();
extern int CFails = 0;


int MacMessage()
{
	HCOSE_MAC hEncObj = COSE_Mac_Init(NULL, NULL);
	char * sz = "This is the content to be used";
	byte rgbSecret[256 / 8] = { 'a', 'b', 'c' };
	byte  rgbKid[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };
	int cbKid = 6;
	size_t cb;
	byte * rgb;

	COSE_Mac_map_put(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(COSE_Algorithm_HMAC_256_256, NULL, NULL), COSE_PROTECT_ONLY, NULL);
	COSE_Mac_SetContent(hEncObj, (byte *) sz, strlen(sz), NULL);

	COSE_Mac_add_shared_secret(hEncObj, COSE_Algorithm_Direct, rgbSecret, sizeof(rgbSecret), rgbKid, cbKid, NULL);

	COSE_Mac_encrypt(hEncObj, NULL);

	cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0) + 1;
	rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);


	FILE * fp = fopen("test.mac.cbor", "wb");
	fwrite(rgb, cb, 1, fp);
	fclose(fp);

	char * szX;
	int cbPrint = 0;
	cn_cbor * cbor = COSE_get_cbor((HCOSE)hEncObj);
	cbPrint = cn_cbor_printer_write(NULL, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, "%s", szX);
	fprintf(stdout, "\r\n");

	COSE_Mac_Free(hEncObj);

	/* */

	int typ;
	hEncObj = (HCOSE_MAC) COSE_Decode(rgb,  (int) cb, &typ, NULL, NULL);

	int iRecipient = 0;
	do {
		HCOSE_RECIPIENT hRecip;

		hRecip = COSE_Mac_GetRecipient(hEncObj, iRecipient, NULL);
		if (hRecip == NULL) break;

		COSE_Recipient_SetKey(hRecip, rgbSecret, sizeof(rgbSecret), NULL);

		COSE_Mac_validate(hEncObj, hRecip, NULL);

		iRecipient += 1;

	} while (true);

	return 1;
}

int SignMessage()
{
	HCOSE_SIGN hEncObj = COSE_Sign_Init(NULL, NULL);
	char * sz = "This is the content to be used";
	size_t cb;
	byte * rgb;

			byte rgbX[] = { 0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba, 0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a, 0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d, 0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d };
		byte rgbY[] = { 0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7, 0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d, 0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c, 0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c };
		byte kid[] = { 0x6d, 0x65, 0x72, 0x69, 0x61, 0x64, 0x6f, 0x63, 0x2e, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x79, 0x62, 0x75, 0x63, 0x6, 0xb4, 0x06, 0x27, 0x56, 0x36, 0xb6, 0xc6, 0x16, 0xe6, 0x42, 0xe6, 0x57, 0x86, 0x16, 0xd7, 0x06, 0x65};
		byte rgbD[] = {0xaf, 0xf9, 0x07, 0xc9, 0x9f, 0x9a, 0xd3, 0xaa, 0xe6, 0xc4, 0xcd, 0xf2, 0x11, 0x22, 0xbc, 0xe2, 0xbd, 0x68, 0xb5, 0x28, 0x3e, 0x69, 0x07, 0x15, 0x4a, 0xd9, 0x11, 0x84, 0x0f, 0xa2, 0x08, 0xcf};
			
			cn_cbor * pkey = cn_cbor_map_create(NULL, NULL);
	cn_cbor_mapput_int(pkey, COSE_Key_Type, cn_cbor_int_create(COSE_Key_Type_EC2, NULL, NULL), NULL, NULL);
	cn_cbor_mapput_int(pkey, -1, cn_cbor_int_create(1, NULL, NULL), NULL, NULL);
	cn_cbor_mapput_int(pkey, -2, cn_cbor_data_create(rgbX, sizeof(rgbX), NULL, NULL), NULL, NULL);
	cn_cbor_mapput_int(pkey, -3, cn_cbor_data_create(rgbY, sizeof(rgbY), NULL, NULL), NULL, NULL);
	cn_cbor_mapput_int(pkey, COSE_Key_ID, cn_cbor_data_create(kid, sizeof(kid), NULL, NULL), NULL, NULL);
	cn_cbor_mapput_int(pkey, -4, cn_cbor_data_create(rgbD, sizeof(rgbD), NULL, NULL), NULL, NULL);

	COSE_Sign_SetContent(hEncObj, (byte *) sz, strlen(sz), NULL);
	COSE_Sign_add_signer(hEncObj, pkey, COSE_Algorithm_ECDSA_SHA_256, NULL);

	COSE_Sign_Sign(hEncObj, NULL);

	cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0) + 1;
	rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);


	FILE * fp = fopen("test.mac.cbor", "wb");
	fwrite(rgb, cb, 1, fp);
	fclose(fp);

	char * szX;
	int cbPrint = 0;
	cn_cbor * cbor = COSE_get_cbor((HCOSE)hEncObj);
	cbPrint = cn_cbor_printer_write(NULL, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, "%s", szX);
	fprintf(stdout, "\r\n");

	COSE_Sign_Free(hEncObj);

	return 1;
}

int EncryptMessage()
{
	HCOSE_ENCRYPT hEncObj = COSE_Encrypt_Init(NULL, NULL);
	byte rgbSecret[128 / 8] = { 'a', 'b', 'c' };
	int cbSecret = 128/8;
	byte  rgbKid[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };
	int cbKid = 6;
	size_t cb;
	byte * rgb;
	char * sz = "This is the content to be used";


	COSE_Encrypt_map_put(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(COSE_Algorithm_AES_CCM_16_64_128, NULL, NULL), COSE_PROTECT_ONLY, NULL);
	COSE_Encrypt_SetContent(hEncObj, (byte *) sz, strlen(sz), NULL);
	COSE_Encrypt_map_put(hEncObj, COSE_Header_IV, cn_cbor_data_create(rgbKid, cbKid, NULL, NULL), COSE_UNPROTECT_ONLY, NULL);

	COSE_Encrypt_add_shared_secret(hEncObj, COSE_Algorithm_Direct, rgbSecret, cbSecret, rgbKid, cbKid, NULL);

	COSE_Encrypt_encrypt(hEncObj, NULL);

	cb = COSE_Encode((HCOSE)hEncObj, NULL, 0, 0) +1;
	rgb = (byte *)malloc(cb);
	cb = COSE_Encode((HCOSE)hEncObj, rgb, 0, cb);


	FILE * fp = fopen("test.cbor", "wb");
	fwrite(rgb, cb, 1, fp);
	fclose(fp);

	char * szX;
	int cbPrint = 0;
	cn_cbor * cbor = COSE_get_cbor((HCOSE) hEncObj);
	cbPrint = cn_cbor_printer_write(NULL, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, "%s", szX);
	fprintf(stdout, "\r\n");

	COSE_Encrypt_Free(hEncObj);

	/* */

	int typ;
	hEncObj = (HCOSE_ENCRYPT) COSE_Decode(rgb, (int) cb, &typ, NULL, NULL);
	
	int iRecipient = 0;
	do {
		HCOSE_RECIPIENT hRecip;

		hRecip = COSE_Encrypt_GetRecipient(hEncObj, iRecipient, NULL);
		if (hRecip == NULL) break;

		COSE_Recipient_SetKey(hRecip, rgbSecret, cbSecret, NULL);

		COSE_Encrypt_decrypt(hEncObj, hRecip, NULL);

		iRecipient += 1;

	} while (true);

	return 1;
}


int main()
{
  	MacMessage();
  	SignMessage();
  	EncryptMessage();

	if (CFails > 0) printf("Failed %d tests\n", CFails);
	else printf("SUCCESS\n");

	exit(CFails);
}
