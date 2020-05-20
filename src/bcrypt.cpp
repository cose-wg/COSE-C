#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "cose_crypto.h"

#if COSE_C_USE_BCRYPT

#include <Windows.h>

bool AES_CCM_Encrypt(COSE_Encrypt *pcose,
	int TSize,
	int LSize,
	int KSize,
	byte *pbAuthData,
	int cbAuthData)
{
	NTSTATUS err;
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_DATA_BLOB_HEADER *pHdr = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {0};
	byte rgbTag[16];
	int cbOut;
	byte *pbOut = nullptr;

	err = BCryptOpenAlgorithmProvider(&hAlg, "AES_CCM", nullptr, 0);
	if (err != 0) {
	error:
		if (pbOut != nullptr)
			free(pbOut);
		if (pHdr != nullptr)
			free(pHdr);
		if (hKey != nullptr)
			BCryptDestroyKey(hKey);
		if (hAlg != nullptr)
			BCryptCloseAlgorithmProvider(hAlg, 0);
		return false;
	}

	pHdr = (BCRYPT_KEY_DATA_BLOB_HEADER *)malloc(sizeof(*pHdr) + KSize / 8);
	if (pHdr == nullptr)
		goto error;
	pHdr->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	pHdr->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
	pHdr->cbKeyData = KSize / 8;
	memcpy(&pHdr[1], pcose->pbKey, pcose->cbKey);

	err = BCryptImportKey(hAlg, nullptr, BCRYPT_KEY_DATA_BLOB, &hKey, nullptr,
		0, pHdr, (sizeof(*pHdr) + KSize / 8), 0);
	if (err != 0)
		goto error;

	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = pcose->pbIV;
	authInfo.cbNonce = pcose->cbIV;
	authInfo.pbAuthData = pbAuthData;
	authInfo.cbAuthData = cbAuthData;
	authInfo.pbTag = rgbTag;
	authInfo.cbTag = TSize / 8;
	authInfo.pbMacContext = nullptr;

	cbOut = pcose->cbContent + TSize / 8;
	pbOut = (byte *)malloc(cbOut);
	if (pbOut == nullptr)
		goto error;

	err = BCryptEncrypt(hKey, pcose->pbContent, pcose->cbContent, &authInfo,
		nullptr, 0, pbOut, cbOut, 0, 0);
	if (err != 0)
		goto error;

	memcpy(&pbOut[pcose->cbContent], rgbTag, TSize / 8);

	cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Ciphertext,
		cn_cbor_data_create(pbOut, cbOut, nullptr), nullptr);

	return true;
}

#endif	// COSE_C_USE_BCRYPT
