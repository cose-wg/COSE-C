/**
* Perform an AES-CCM Decryption operation
*
* @param[in]   COSE_Encrypt Pointer to COSE Encryption context object
* @param[in]   int          Size of the Tag value to be create
* @param[in]   int          Size of the Message Length field
* @param[in]   byte *       Pointer to authenticated data structure
* @param[in]   int          Size of authenticated data structure
* @return                   Did the function succeed?
*/
bool AES_CCM_Decrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbKey, int cbitKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr);
bool AES_GCM_Decrypt(COSE_Encrypt * pcose, const byte * pbKey, int cbKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr);
bool AES_KW_Decrypt(COSE_Encrypt * pcose, const byte * pbKeyIn, size_t cbitKey, byte * pbKeyOut, int * pcbKeyOut, cose_errback * perr);

/**
* Perform an AES-CCM Encryption operation
*
* @param[in]   COSE_Encrypt Pointer to COSE Encryption context object
* @param[in]   int          Size of the Tag value to be create
* @param[in]   int          Size of the Message Length field
* @param[in]   byte *       Pointer to authenticated data structure
* @param[in]   int          Size of authenticated data structure
* @return                   Did the function succeed?
*/
bool AES_CCM_Encrypt(COSE_Encrypt * pcose, int TSize, int LSize, int cbitKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr);
bool AES_GCM_Encrypt(COSE_Encrypt * pcose, int KeySize,const byte * pbAuthData, int cbAuthData, cose_errback * perr);
bool AES_KW_Encrypt(COSE_RecipientInfo * pcose, const byte * pbKeyIn, int cbitKey, const byte *  pbContent, int  cbContent, cose_errback * perr);


extern bool AES_CMAC_Validate(COSE_MacMessage * pcose, int KeySize, int TagSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);

extern bool AES_CBC_MAC_Create(COSE_MacMessage * pcose, int KeySize, int TagSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);
extern bool AES_CBC_MAC_Validate(COSE_MacMessage * pcose, int KeySize, int TagSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);

/**
* Perform an HMAC Creation operation
*
* @param[in]	COSE_Encrypt	Pointer to COSE Encryption context object
* @param[in]	int				Hash function to be used
* @param[in]	int				Size of Tag value to be created
* @param[in]	byte *			Pointer to authenticated data structure
* @param[in]	int				Size of authenticated data structure
* @param[in]	cose_errback *	Error return location
* @return						Did the function succeed?
*/
bool HMAC_Create(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);
bool HMAC_Validate(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);

/**
* Perform a signature operation
*
* @param[in]	COSE_SignerInfo Pointer to COSE SignerInfo context object
* @param[in]	byte *			Pointer to text to be signed
* @param[in]	size_t			size of text to be signed
* @param[in]	cose_errback *	Error return location
* @return						Did the function succeed?
*/
bool ECDSA_Sign(COSE_SignerInfo * pSigner, int cbitsDigest, const byte * rgbToSign, size_t cbToSign, cose_errback * perr);
bool ECDSA_Verify(COSE_SignerInfo * pSigner, int cbitsDigest, const byte * rgbToSign, size_t cbToSign, const byte * rgbSig, size_t cbSig, cose_errback * perr);

/**
*  Generate random bytes in a buffer
*
* @param[in]   byte *      Pointer to buffer to be filled
* @param[in]   size_t      Size of buffer to be filled
* @return                  none
*/
void rand_bytes(byte * pb, size_t cb);
