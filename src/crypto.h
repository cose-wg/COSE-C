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
bool AES_CCM_Decrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbAuthData, int cbAuthData);

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
bool AES_CCM_Encrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbAuthData, int cbAuthData);

/**
*  Generate random bytes in a buffer
*
* @param[in]   byte *      Pointer to buffer to be filled
* @param[in]   size_t      Size of buffer to be filled
* @return                  none
*/
void rand_bytes(byte * pb, size_t cb);
