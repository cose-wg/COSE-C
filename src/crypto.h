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
bool AES_CCM_Decrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbKey, int cbKey, const byte * pbAuthData, int cbAuthData, cose_errback * perr);

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
bool AES_CCM_Encrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);


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
bool HMAC_Create(COSE_Encrypt * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);
bool HMAC_Validate(COSE_Encrypt * pcose, int HSize, int TSize, const byte * pbAuthData, int cbAuthData, cose_errback * perr);

/**
* Perform a signature operation
*
* @param[in]	COSE_SignerInfo Pointer to COSE SignerInfo context object
* @param[in]	byte *			Pointer to text to be signed
* @param[in]	size_t			size of text to be signed
* @param[in]	cose_errback *	Error return location
* @return						Did the function succeed?
*/
bool ECDSA_Sign(COSE_SignerInfo * pSigner, const byte * rgbToSign, size_t cbToSign, cose_errback * perr);

/**
*  Generate random bytes in a buffer
*
* @param[in]   byte *      Pointer to buffer to be filled
* @param[in]   size_t      Size of buffer to be filled
* @return                  none
*/
void rand_bytes(byte * pb, size_t cb);
