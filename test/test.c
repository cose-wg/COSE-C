// test.cpp : Defines the entry point for the console application.
//

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose.h>
#include <cn-cbor\cn-cbor.h>

extern int EncryptMessage();

int main(int argc, char * argv[])
{
	MacMessage();
	SignMessage();
	EncryptMessage();
	return 0;
}

int MacMessage()
{
	HCOSE_MAC hEncObj = COSE_Mac_Init(NULL, NULL);
	char * sz = "This is the content to be used";
	byte rgbSecret[256 / 8] = { 'a', 'b', 'c' };
	byte  rgbKid[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };
	int cbKid = 6;
	ssize_t cb;
	byte * rgb;

	COSE_Mac_map_put(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(COSE_Algorithm_HMAC_256_256, NULL, NULL), COSE_PROTECT_ONLY, NULL);
	COSE_Mac_SetContent(hEncObj, sz, strlen(sz), NULL);

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
	fprintf(stdout, szX);
	fprintf(stdout, "\r\n");

	COSE_Mac_Free(hEncObj);

}

int SignMessage()
{
	HCOSE_SIGN hEncObj = COSE_Sign_Init(NULL, NULL);


}

int EncryptMessage()
{
	HCOSE_ENCRYPT hEncObj = COSE_Encrypt_Init(NULL, NULL);
	byte rgbSecret[128 / 8] = { 'a', 'b', 'c' };
	int cbSecret = 128/8;
	byte  rgbKid[6] = { 'a', 'b', 'c', 'd', 'e', 'f' };
	int cbKid = 6;
	ssize_t cb;
	byte * rgb;
	char * sz = "This is the content to be used";


	COSE_Encrypt_map_put(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(COSE_Algorithm_AES_CCM_16_64_128, NULL, NULL), COSE_PROTECT_ONLY, NULL);
	COSE_Encrypt_SetContent(hEncObj, sz, strlen(sz), NULL);
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
	//cbPrint = cn_cbor_printer_write(NULL, 0, cbor, "  ", "\r\n");
	szX = malloc(cbPrint);
	//cn_cbor_printer_write(szX, cbPrint, cbor, "  ", "\r\n");
	fprintf(stdout, szX);
	fprintf(stdout, "\r\n");

	COSE_Encrypt_Free(hEncObj);

	/* */

	int typ;
	hEncObj = (HCOSE_ENCRYPT) COSE_Decode(rgb, cb, &typ, NULL, NULL);
	
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
