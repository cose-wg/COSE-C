#include <stdlib.h>
#ifdef __MBED__
#include <string.h>
#else
#include <memory.h>
#endif

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "cose_crypto.h"

#if INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0 || INCLUDE_MAC || INCLUDE_MAC0
static bool BuildContextBytes(COSE *pcose,
	int algID,
	size_t cbitKey,
	byte **ppbContext,
	size_t *pcbContext,
	CBOR_CONTEXT_COMMA cose_errback *perr);
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
COSE *RecipientRoot = nullptr;

/*! \private
 * @brief Test if a HCOSE_RECIPIENT handle is valid
 *
 *  Internal function to test if a recipient handle is valid.
 *  This will start returning invalid results and cause the code to
 *  crash if handles are not released before the memory that underlies them
 *  is deallocated.  This is an issue of a block allocator is used since
 *  in that case it is common to allocate memory but never to de-allocate it
 *  and just do that in a single big block.
 *
 *  @param h handle to be validated
 *  @returns result of check
 */
bool IsValidRecipientHandle(HCOSE_RECIPIENT h)
{
	COSE_RecipientInfo *p = (COSE_RecipientInfo *)h;

	if (p == nullptr) {
		return false;
	}
	return _COSE_IsInList(RecipientRoot, &p->m_encrypt.m_message);
}

HCOSE_RECIPIENT COSE_Recipient_Init(COSE_INIT_FLAGS flags,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	if (false) {
	errorReturn:
		return nullptr;
	}

	CHECK_CONDITION(flags == COSE_INIT_FLAGS_NONE, COSE_ERR_INVALID_PARAMETER);
	COSE_RecipientInfo *pobj = (COSE_RecipientInfo *)COSE_CALLOC(
		1, sizeof(COSE_RecipientInfo), context);
	CHECK_CONDITION(pobj != nullptr, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(
			static_cast<COSE_INIT_FLAGS>(COSE_INIT_FLAGS_NO_CBOR_TAG | flags),
			&pobj->m_encrypt.m_message, COSE_recipient_object,
			CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Recipient_Free(pobj);
		return nullptr;
	}

	_COSE_InsertInList(&RecipientRoot, &pobj->m_encrypt.m_message);
	return (HCOSE_RECIPIENT)pobj;
}

bool COSE_Recipient_Free(HCOSE_RECIPIENT hRecipient)
{
	if (IsValidRecipientHandle(hRecipient)) {
		COSE_RecipientInfo *p = (COSE_RecipientInfo *)hRecipient;

		if (p->m_encrypt.m_message.m_refCount > 1) {
			p->m_encrypt.m_message.m_refCount--;
			return true;
		}

		_COSE_RemoveFromList(&RecipientRoot, &p->m_encrypt.m_message);

		_COSE_Recipient_Free(p);
		return true;
	}

	return false;
}

HCOSE_RECIPIENT COSE_Recipient_from_shared_secret(byte *rgbKey,
	int cbKey,
	byte *rgbKid,
	int cbKid,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	HCOSE_RECIPIENT hRecipient = nullptr;

	hRecipient = COSE_Recipient_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA perr);
	if (hRecipient == nullptr) {
		goto errorReturn;
	}

	if (!COSE_Recipient_SetKey_secret(
			hRecipient, rgbKey, cbKey, rgbKid, cbKid, perr)) {
		goto errorReturn;
	}

	return hRecipient;

errorReturn:
	if (hRecipient != nullptr) {
		COSE_Recipient_Free(hRecipient);
	}
	return nullptr;
}

COSE_RecipientInfo *_COSE_Recipient_Init_From_Object(cn_cbor *cbor,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	COSE_RecipientInfo *pRecipient = nullptr;

	pRecipient = (COSE_RecipientInfo *)COSE_CALLOC(
		1, sizeof(COSE_RecipientInfo), context);
	CHECK_CONDITION(pRecipient != nullptr, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

	if (_COSE_Enveloped_Init_From_Object(cbor, &pRecipient->m_encrypt,
			CBOR_CONTEXT_PARAM_COMMA perr) == nullptr) {
		goto errorReturn;
	}

	_COSE_InsertInList(&RecipientRoot, &pRecipient->m_encrypt.m_message);

	return pRecipient;

errorReturn:
	if (pRecipient != nullptr) {
		_COSE_Recipient_Free(pRecipient);
	}
	return nullptr;
}

void _COSE_Recipient_Free(COSE_RecipientInfo *pRecipient)
{
	if (pRecipient->m_encrypt.m_message.m_refCount > 1) {
		pRecipient->m_encrypt.m_message.m_refCount--;
		return;
	}

	_COSE_Enveloped_Release(&pRecipient->m_encrypt);
	if (pRecipient->m_pkey != nullptr) {
		COSE_KEY_Free((HCOSE_KEY)pRecipient->m_pkey);
	}
	if (pRecipient->m_pkeyStatic != nullptr) {
		COSE_KEY_Free((HCOSE_KEY)pRecipient->m_pkeyStatic);
	}

	COSE_FREE(pRecipient, &pRecipient->m_encrypt.m_message.m_allocContext);
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0 || INCLUDE_MAC || INCLUDE_MAC0
#if defined(USE_HKDF_SHA2) || defined(USE_HKDF_AES)
/**
 * Perform an AES-CCM Decryption operation
 *
 * @param[in]	COSE *		Pointer to COSE Encryption context object
 * @param[in]	int			Alorithm key is being generated for
 * @param[in]	cn_cbor *	Private key
 * @param[in]	cn_cbor *	Public Key
 * @param[out]	byte *		Buffer to return new key in
 * @param[in]	size_t       Size of key to create in bits
 * @param[in]    size_t		Size of digest function
 * @param[in]	cbor_context * Allocation context
 * @param[out]	cose_errback * Returned error information
 * @return                   Did the function succeed?
 */

static bool HKDF_X(COSE *pCose,
	bool fHMAC,
	bool fECDH,
	bool fStatic,
	bool fSend,
	int algResult,
	COSE_KEY *pKeyPrivate,
	COSE_KEY *pKeyPublic,
	byte *pbKey,
	size_t cbitKey,
	size_t cbitHash,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	byte *pbContext = nullptr;
	size_t cbContext;
	bool fRet = false;
	const cn_cbor *cn;
	byte rgbDigest[512 / 8];
	size_t cbDigest;
	byte *pbSecret = nullptr;
	size_t cbSecret = 0;
	COSE_KEY *pkeyMessage = NULL;

	if (!BuildContextBytes(pCose, algResult, cbitKey, &pbContext, &cbContext,
			CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	if (fECDH) {
#ifdef USE_ECDH

		if (pKeyPrivate != nullptr && pKeyPrivate->m_cborKey != nullptr) {
			cn = cn_cbor_mapget_int(pKeyPrivate->m_cborKey, COSE_Key_Type);
			CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_UINT),
				COSE_ERR_INVALID_PARAMETER);
			CHECK_CONDITION(cn->v.uint == COSE_Key_Type_EC2 ||
								cn->v.uint == COSE_Key_Type_OKP,
				COSE_ERR_INVALID_PARAMETER);
		}

		if (pKeyPublic != nullptr && pKeyPublic->m_cborKey != nullptr) {
			cn = cn_cbor_mapget_int(pKeyPublic->m_cborKey, COSE_Key_Type);
			CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_UINT),
				COSE_ERR_INVALID_PARAMETER);
			CHECK_CONDITION(cn->v.uint == COSE_Key_Type_EC2 ||
								cn->v.uint == COSE_Key_Type_OKP,
				COSE_ERR_INVALID_PARAMETER);
		}

		if (fSend) {
			CHECK_CONDITION(pKeyPublic != nullptr, COSE_ERR_INVALID_PARAMETER);
			pkeyMessage = pKeyPrivate;

			if (!ECDH_ComputeSecret(pCose, &pkeyMessage, pKeyPublic, &pbSecret,
					&cbSecret, CBOR_CONTEXT_PARAM_COMMA perr)) {
				if (pkeyMessage != nullptr && pKeyPrivate == nullptr) {
					COSE_KEY_Free((HCOSE_KEY)pkeyMessage);
				}
				goto errorReturn;
			}
			if (!fStatic && pkeyMessage->m_cborKey->parent == nullptr) {
				cn_cbor_errback cborError;
				cn_cbor *pdup = pkeyMessage->m_cborKey;
				if (pKeyPrivate == nullptr) {
					pkeyMessage->m_cborKey = nullptr;
				}
				else {
					pdup = cn_cbor_clone(pkeyMessage->m_cborKey,
						CBOR_CONTEXT_PARAM_COMMA & cborError);
					CHECK_CONDITION_CBOR(pdup != nullptr, cborError);
				}
				if (pKeyPrivate == nullptr) {
					COSE_KEY_Free((HCOSE_KEY)pkeyMessage);
				}
				if (!_COSE_map_put(pCose, COSE_Header_ECDH_EPHEMERAL, pdup,
						COSE_UNPROTECT_ONLY, perr)) {
					CN_CBOR_FREE(pdup, context);
					goto errorReturn;
				}
			}
		}
		else {
			CHECK_CONDITION(pKeyPrivate != nullptr, COSE_ERR_INVALID_PARAMETER);
			pkeyMessage = pKeyPublic;

			if (pKeyPublic == nullptr) {
				cn_cbor *cborKey = _COSE_map_get_int(pCose,
					fStatic ? COSE_Header_ECDH_STATIC
							: COSE_Header_ECDH_EPHEMERAL,
					COSE_BOTH, perr);
				CHECK_CONDITION(cborKey != nullptr, COSE_ERR_OUT_OF_MEMORY);

				pkeyMessage = (COSE_KEY *)COSE_KEY_FromCbor(
					cborKey, CBOR_CONTEXT_PARAM_COMMA perr);
				if (pkeyMessage == nullptr) {
					goto errorReturn;
				}
			}

			if (!ECDH_ComputeSecret(pCose, &pKeyPrivate, pkeyMessage, &pbSecret,
					&cbSecret, CBOR_CONTEXT_PARAM_COMMA perr)) {
				if (pKeyPublic == nullptr) {
					pkeyMessage->m_cborKey = nullptr;
					COSE_KEY_Free((HCOSE_KEY)pkeyMessage);
				}
				goto errorReturn;
			}
			if (pKeyPublic == nullptr) {
				pkeyMessage->m_cborKey = nullptr;
				COSE_KEY_Free((HCOSE_KEY)pkeyMessage);
			}
		}
#else
		goto errorReturn;
#endif
	}
	else {
		CHECK_CONDITION(pKeyPrivate != nullptr, COSE_ERR_INVALID_PARAMETER);
		cn = cn_cbor_mapget_int(pKeyPrivate->m_cborKey, COSE_Key_Type);
		CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_UINT),
			COSE_ERR_INVALID_PARAMETER);
		CHECK_CONDITION(
			cn->v.uint == COSE_Key_Type_OCTET, COSE_ERR_INVALID_PARAMETER);

		CHECK_CONDITION(cn->v.sint == 4, COSE_ERR_INVALID_PARAMETER);

		cn = cn_cbor_mapget_int(pKeyPrivate->m_cborKey, -1);
		CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_BYTES),
			COSE_ERR_INVALID_PARAMETER);
		pbSecret = (byte *)cn->v.bytes;
		cbSecret = cn->length;
	}

	if (fHMAC) {
#ifdef USE_HKDF_SHA2
		if (!HKDF_Extract(pCose, pbSecret, cbSecret, cbitHash, rgbDigest,
				&cbDigest, CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}

		if (!HKDF_Expand(pCose, cbitHash, rgbDigest, cbDigest, pbContext,
				cbContext, pbKey, cbitKey / 8, perr)) {
			goto errorReturn;
		}
#else
		goto errorReturn;
#endif
	}
	else {
#ifdef USE_HKDF_AES
		if (!HKDF_AES_Expand(pCose, cbitHash, pbSecret, cbSecret, pbContext,
				cbContext, pbKey, cbitKey / 8, perr)) {
			goto errorReturn;
		}
#else
		goto errorReturn;
#endif
	}
	fRet = true;

errorReturn:
	if (fECDH && pbSecret != nullptr) {
		memset(pbSecret, 0, cbSecret);
		COSE_FREE(pbSecret, context);
	}
	memset(rgbDigest, 0, sizeof(rgbDigest));
	if (pbContext != nullptr) {
		COSE_FREE(pbContext, context);
	}
	return fRet;
}
#endif	// defined(USE_HKDF_SHA2) || defined(USE_HKDF_AES)

bool _COSE_Recipient_decrypt(COSE_RecipientInfo *pRecip,
	COSE_RecipientInfo *pRecipUse,
	int algIn,
	size_t cbitKeyOut,
	byte *pbKeyOut,
	cose_errback *perr)
{
	UNUSED(pRecipUse);
	int alg;
	const cn_cbor *cn = nullptr;
	COSE_RecipientInfo *pRecip2;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context;
#endif
	byte *pbAuthData = nullptr;
	byte *pbProtected = nullptr;
	COSE_Enveloped *pcose = &pRecip->m_encrypt;
	cn_cbor *cnBody = nullptr;
	byte *pbContext = nullptr;
	byte *pbSecret = nullptr;
	size_t cbKey2;
	byte *pbKeyX = nullptr;
	int cbitKeyX = 0;
	byte rgbKey[256 / 8];

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#else
	UNUSED(pcose);
#endif

	cn = _COSE_map_get_int(
		&pRecip->m_encrypt.m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == nullptr) {
	errorReturn:
		if (pbContext != nullptr) {
			COSE_FREE(pbContext, context);
		}
		if (pbProtected != nullptr) {
			COSE_FREE(pbProtected, context);
		}
		if (pbAuthData != nullptr) {
			COSE_FREE(pbAuthData, context);
		}
		if (pbSecret != nullptr) {
			COSE_FREE(pbSecret, context);
		}
		if (pbKeyX != nullptr) {
			COSE_FREE(pbKeyX, context);
		}
		return false;
	}
	CHECK_CONDITION(cn->type != CN_CBOR_TEXT, COSE_ERR_UNKNOWN_ALGORITHM);
	CHECK_CONDITION((cn->type == CN_CBOR_UINT) || (cn->type == CN_CBOR_INT),
		COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn->v.uint;

	CHECK_CONDITION(pbKeyOut != nullptr, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
		case COSE_Algorithm_Direct:
			CHECK_CONDITION(
				pRecip->m_pkey != nullptr, COSE_ERR_INVALID_PARAMETER);
			cn = cn_cbor_mapget_int(pRecip->m_pkey->m_cborKey, -1);
			CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_BYTES),
				COSE_ERR_INVALID_PARAMETER);
			CHECK_CONDITION(((size_t)cn->length == cbitKeyOut / 8),
				COSE_ERR_INVALID_PARAMETER);
			memcpy(pbKeyOut, cn->v.bytes, cn->length);

			return true;

#ifdef USE_AES_KW_128
		case COSE_Algorithm_AES_KW_128:
			cbitKeyX = 128;
			break;
#endif

#ifdef USE_AES_KW_192
		case COSE_Algorithm_AES_KW_192:
			cbitKeyX = 192;
			break;
#endif

#ifdef USE_AES_KW_256
		case COSE_Algorithm_AES_KW_256:
			cbitKeyX = 192;
			break;
#endif

#ifdef USE_Direct_HKDF_AES_128
		case COSE_Algorithm_Direct_HKDF_AES_128:
			break;
#endif

#ifdef USE_Direct_HKDF_AES_256
		case COSE_Algorithm_Direct_HKDF_AES_256:
			break;
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_256
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
			break;
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_512
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
			break;
#endif

#ifdef USE_ECDH_ES_HKDF_256
		case COSE_Algorithm_ECDH_ES_HKDF_256:
			break;
#endif

#ifdef USE_ECDH_ES_HKDF_512
		case COSE_Algorithm_ECDH_ES_HKDF_512:
			break;
#endif

#ifdef USE_ECDH_SS_HKDF_256
		case COSE_Algorithm_ECDH_SS_HKDF_256:
			break;
#endif

#ifdef USE_ECDH_SS_HKDF_512
		case COSE_Algorithm_ECDH_SS_HKDF_512:
			break;
#endif

#ifdef USE_ECDH_ES_A128KW
		case COSE_Algorithm_ECDH_ES_A128KW:
			break;
#endif

#ifdef USE_ECDH_ES_A192KW
		case COSE_Algorithm_ECDH_ES_A192KW:
			break;
#endif

#ifdef USE_ECDH_ES_A256KW
		case COSE_Algorithm_ECDH_ES_A256KW:
			break;
#endif

#ifdef USE_ECDH_SS_A128KW
		case COSE_Algorithm_ECDH_SS_A128KW:
			break;
#endif

#ifdef USE_ECDH_SS_A192KW
		case COSE_Algorithm_ECDH_SS_A192KW:
			break;
#endif

#ifdef USE_ECDH_SS_A256KW
		case COSE_Algorithm_ECDH_SS_A256KW:
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			break;
	}

	if (pcose->m_recipientFirst != nullptr) {
		//  If there is a recipient - ask it for the key
		CHECK_CONDITION(cbitKeyX != 0, COSE_ERR_INVALID_PARAMETER);
		pbKeyX = (byte *)COSE_CALLOC(cbitKeyX / 8, 1, context);
		CHECK_CONDITION(pbKeyX != nullptr, COSE_ERR_OUT_OF_MEMORY);
		cose_errback error = {COSE_ERR_NONE};
		cose_error errorFound = COSE_ERR_NONE;

		for (pRecip2 = pcose->m_recipientFirst; pRecip2 != nullptr;
			 pRecip2 = pRecip->m_recipientNext) {
			if (_COSE_Recipient_decrypt(
					pRecip2, nullptr, alg, cbitKeyX, pbKeyX, &error)) {
				break;
			}
			if (error.err == COSE_ERR_NO_COMPRESSED_POINTS ||
				error.err == COSE_ERR_UNKNOWN_ALGORITHM) {
				errorFound = error.err;
			}
		}

		if (errorFound != COSE_ERR_NONE) {
			perr->err = errorFound;
			goto errorReturn;
		}
		CHECK_CONDITION(pRecip2 != nullptr, COSE_ERR_NO_RECIPIENT_FOUND);
	}

	cnBody = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION(cnBody != nullptr, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
#ifdef USE_AES_KW_128
		case COSE_Algorithm_AES_KW_128:
			if (pbKeyX != nullptr) {
				size_t x = (int)(cbitKeyOut / 8);
				if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, pbKeyX, cbitKeyX,
						cnBody->v.bytes, cnBody->length, pbKeyOut, &x, perr)) {
					goto errorReturn;
				}
			}
			else {
				CHECK_CONDITION(
					pRecip->m_pkey != nullptr, COSE_ERR_INVALID_PARAMETER);
				size_t x = cbitKeyOut / 8;
				cn = cn_cbor_mapget_int(pRecip->m_pkey->m_cborKey, -1);
				CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_BYTES),
					COSE_ERR_INVALID_PARAMETER);

				if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, cn->v.bytes,
						cn->length * 8, cnBody->v.bytes, cnBody->length,
						pbKeyOut, &x, perr)) {
					goto errorReturn;
				}
			}
			break;
#endif

#ifdef USE_AES_KW_192
		case COSE_Algorithm_AES_KW_192:
			if (pbKeyX != nullptr) {
				size_t x = cbitKeyOut / 8;
				if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, pbKeyX, cbitKeyX,
						cnBody->v.bytes, cnBody->length, pbKeyOut, &x, perr)) {
					goto errorReturn;
				}
			}
			else {
				CHECK_CONDITION(
					pRecip->m_pkey != nullptr, COSE_ERR_INVALID_PARAMETER);
				size_t x = cbitKeyOut / 8;
				cn = cn_cbor_mapget_int(pRecip->m_pkey->m_cborKey, -1);
				CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_BYTES),
					COSE_ERR_INVALID_PARAMETER);

				if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, cn->v.bytes,
						cn->length * 8, cnBody->v.bytes, cnBody->length,
						pbKeyOut, &x, perr)) {
					goto errorReturn;
				}
			}
			break;
#endif

#ifdef USE_AES_KW_256
		case COSE_Algorithm_AES_KW_256:
			if (pbKeyX != nullptr) {
				size_t x = cbitKeyOut / 8;
				if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, pbKeyX, cbitKeyX,
						cnBody->v.bytes, cnBody->length, pbKeyOut, &x, perr)) {
					goto errorReturn;
				}
			}
			else {
				CHECK_CONDITION(
					pRecip->m_pkey != nullptr, COSE_ERR_INVALID_PARAMETER);
				size_t x = cbitKeyOut / 8;
				cn = cn_cbor_mapget_int(pRecip->m_pkey->m_cborKey, -1);
				CHECK_CONDITION((cn != nullptr) && (cn->type == CN_CBOR_BYTES),
					COSE_ERR_INVALID_PARAMETER);

				if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, cn->v.bytes,
						cn->length * 8, cnBody->v.bytes, cnBody->length,
						pbKeyOut, &x, perr)) {
					goto errorReturn;
				}
			}
			break;
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_256
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
			if (!HKDF_X(&pcose->m_message, true, false, false, false, algIn,
					pRecip->m_pkey, pRecip->m_pkeyStatic, pbKeyOut, cbitKeyOut,
					256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_512
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
			if (!HKDF_X(&pcose->m_message, true, false, false, false, algIn,
					pRecip->m_pkey, pRecip->m_pkeyStatic, pbKeyOut, cbitKeyOut,
					512, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_Direct_HKDF_AES_128
		case COSE_Algorithm_Direct_HKDF_AES_128:
			if (!HKDF_X(&pcose->m_message, false, false, false, false, algIn,
					pRecip->m_pkey, pRecip->m_pkeyStatic, pbKeyOut, cbitKeyOut,
					128, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_Direct_HKDF_AES_256
		case COSE_Algorithm_Direct_HKDF_AES_256:
			if (!HKDF_X(&pcose->m_message, false, false, false, false, algIn,
					pRecip->m_pkey, nullptr, pbKeyOut, cbitKeyOut, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_HKDF_256
		case COSE_Algorithm_ECDH_ES_HKDF_256:
			if (!HKDF_X(&pcose->m_message, true, true, false, false, algIn,
					pRecip->m_pkey, nullptr, pbKeyOut, cbitKeyOut, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_HKDF_512
		case COSE_Algorithm_ECDH_ES_HKDF_512:
			if (!HKDF_X(&pcose->m_message, true, true, false, false, algIn,
					pRecip->m_pkey, nullptr, pbKeyOut, cbitKeyOut, 512,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_HKDF_256
		case COSE_Algorithm_ECDH_SS_HKDF_256:
			if (!HKDF_X(&pcose->m_message, true, true, true, false, algIn,
					pRecip->m_pkey, pRecip->m_pkeyStatic, pbKeyOut, cbitKeyOut,
					256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_HKDF_512
		case COSE_Algorithm_ECDH_SS_HKDF_512:
			if (!HKDF_X(&pcose->m_message, true, true, true, false, algIn,
					pRecip->m_pkey, pRecip->m_pkeyStatic, pbKeyOut, cbitKeyOut,
					512, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_A128KW
		case COSE_Algorithm_ECDH_ES_A128KW:
			if (!HKDF_X(&pcose->m_message, true, true, false, false,
					COSE_Algorithm_AES_KW_128, pRecip->m_pkey, nullptr, rgbKey,
					128, 256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, rgbKey, 128,
					cnBody->v.bytes, cnBody->length, pbKeyOut, &cbKey2, perr)) {
				goto errorReturn;
			}

			break;
#endif

#ifdef USE_ECDH_ES_A192KW
		case COSE_Algorithm_ECDH_ES_A192KW:
			if (!HKDF_X(&pcose->m_message, true, true, false, false,
					COSE_Algorithm_AES_KW_192, pRecip->m_pkey, nullptr, rgbKey,
					192, 256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, rgbKey, 192,
					cnBody->v.bytes, cnBody->length, pbKeyOut, &cbKey2, perr)) {
				goto errorReturn;
			}

			break;
#endif

#ifdef USE_ECDH_ES_A256KW
		case COSE_Algorithm_ECDH_ES_A256KW:
			if (!HKDF_X(&pcose->m_message, true, true, false, false,
					COSE_Algorithm_AES_KW_256, pRecip->m_pkey, nullptr, rgbKey,
					256, 256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, rgbKey, 256,
					cnBody->v.bytes, cnBody->length, pbKeyOut, &cbKey2, perr)) {
				goto errorReturn;
			}

			break;
#endif

#ifdef USE_ECDH_SS_A128KW
		case COSE_Algorithm_ECDH_SS_A128KW:
			if (!HKDF_X(&pcose->m_message, true, true, true, false,
					COSE_Algorithm_AES_KW_128, pRecip->m_pkey,
					pRecip->m_pkeyStatic, rgbKey, 128, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, rgbKey, 128,
					cnBody->v.bytes, cnBody->length, pbKeyOut, &cbKey2, perr)) {
				goto errorReturn;
			}

			break;
#endif

#ifdef USE_ECDH_SS_A192KW
		case COSE_Algorithm_ECDH_SS_A192KW:
			if (!HKDF_X(&pcose->m_message, true, true, true, false,
					COSE_Algorithm_AES_KW_192, pRecip->m_pkey,
					pRecip->m_pkeyStatic, rgbKey, 192, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, rgbKey, 192,
					cnBody->v.bytes, cnBody->length, pbKeyOut, &cbKey2, perr)) {
				goto errorReturn;
			}

			break;
#endif

#ifdef USE_ECDH_SS_A256KW
		case COSE_Algorithm_ECDH_SS_A256KW:
			if (!HKDF_X(&pcose->m_message, true, true, true, false,
					COSE_Algorithm_AES_KW_256, pRecip->m_pkey,
					pRecip->m_pkeyStatic, rgbKey, 256, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}

			if (!AES_KW_Decrypt((COSE_Enveloped *)pcose, rgbKey, 256,
					cnBody->v.bytes, cnBody->length, pbKeyOut, &cbKey2, perr)) {
				goto errorReturn;
			}

			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			break;
	}

	if (pbKeyX != nullptr) {
		COSE_FREE(pbKeyX, context);
	}

	return true;
}

bool _COSE_Recipient_encrypt(COSE_RecipientInfo *pRecipient,
	const byte *pbContent,
	size_t cbContent,
	cose_errback *perr)
{
	int alg;
	int t = 0;
	COSE_RecipientInfo *pri;
	const cn_cbor *cn_Alg = nullptr;
	byte *pbAuthData = nullptr;
	cn_cbor *ptmp = nullptr;
	size_t cbitKey;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = nullptr;
#endif
	cn_cbor_errback cbor_error;
	bool fRet = false;
	byte *pbContext = nullptr;
	byte rgbKey[256 / 8];
	byte *pbSecret = nullptr;
	byte *pbKey = nullptr;
	size_t cbKey = 0;

#ifdef USE_CBOR_CONTEXT
	context = &pRecipient->m_encrypt.m_message.m_allocContext;
#endif	// USE_CBOR_CONTEXT

	cn_Alg = _COSE_map_get_int(&pRecipient->m_encrypt.m_message,
		COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn_Alg == nullptr) {
	errorReturn:
		memset(rgbKey, 0, sizeof(rgbKey));
		if (pbKey != nullptr) {
			memset(pbKey, 0, cbKey);
			COSE_FREE(pbKey, context);
		}
		if (pbSecret != nullptr) {
			COSE_FREE(pbSecret, context);
		}
		if (pbContext != nullptr) {
			COSE_FREE(pbContext, context);
		}
		if (pbAuthData != nullptr) {
			COSE_FREE(pbAuthData, context);
		}
		if (ptmp != nullptr) {
			cn_cbor_free(ptmp CBOR_CONTEXT_PARAM);
		}
		return fRet;
	}

	CHECK_CONDITION(cn_Alg->type != CN_CBOR_TEXT, COSE_ERR_UNKNOWN_ALGORITHM);
	CHECK_CONDITION(
		(cn_Alg->type == CN_CBOR_UINT) || (cn_Alg->type == CN_CBOR_INT),
		COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn_Alg->v.uint;

	//  Get the key size

	switch (alg) {
		case COSE_Algorithm_Direct:
#ifdef USE_Direct_HKDF_HMAC_SHA_256
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_512
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
#endif
#ifdef USE_Direct_HKDF_AES_128
		case COSE_Algorithm_Direct_HKDF_AES_128:
#endif
#ifdef USE_Direct_HKDF_AES_256
		case COSE_Algorithm_Direct_HKDF_AES_256:
#endif
#ifdef USE_ECDH_ES_HKDF_256
		case COSE_Algorithm_ECDH_ES_HKDF_256:
#endif
#ifdef USE_ECDH_ES_HKDF_512
		case COSE_Algorithm_ECDH_ES_HKDF_512:
#endif
#ifdef USE_ECDH_SS_HKDF_256
		case COSE_Algorithm_ECDH_SS_HKDF_256:
#endif
#ifdef USE_ECDH_SS_HKDF_512
		case COSE_Algorithm_ECDH_SS_HKDF_512:
#endif
			//  This is a NOOP
			cbitKey = 0;
			CHECK_CONDITION(pRecipient->m_encrypt.m_recipientFirst == nullptr,
				COSE_ERR_INVALID_PARAMETER);
			break;

#ifdef USE_AES_KW_128
		case COSE_Algorithm_AES_KW_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_ECDH_ES_A128KW
		case COSE_Algorithm_ECDH_ES_A128KW:
			cbitKey = 128;
			break;
#endif

#ifdef USE_ECDH_SS_A128KW
		case COSE_Algorithm_ECDH_SS_A128KW:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_KW_192
		case COSE_Algorithm_AES_KW_192:
			cbitKey = 192;
			break;
#endif

#ifdef USE_ECDH_ES_A192KW
		case COSE_Algorithm_ECDH_ES_A192KW:
			cbitKey = 192;
			break;
#endif

#ifdef USE_ECDH_SS_A192KW
		case COSE_Algorithm_ECDH_SS_A192KW:
			cbitKey = 192;
			break;
#endif

#ifdef USE_AES_KW_256
		case COSE_Algorithm_AES_KW_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_ECDH_ES_A256KW
		case COSE_Algorithm_ECDH_ES_A256KW:
			cbitKey = 256;
			break;
#endif

#ifdef USE_ECDH_SS_A256KW
		case COSE_Algorithm_ECDH_SS_A256KW:
			cbitKey = 256;
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}

	//  If we are doing direct encryption - then recipient generates the key

	if (pRecipient->m_encrypt.m_recipientFirst != nullptr) {
		t = 0;
		for (pri = pRecipient->m_encrypt.m_recipientFirst; pri != nullptr;
			 pri = pri->m_recipientNext) {
			if (pri->m_encrypt.m_message.m_flags & 1) {
				t |= 1;
				pbKey =
					_COSE_RecipientInfo_generateKey(pri, alg, cbitKey, perr);
				if (pbKey == nullptr) {
					goto errorReturn;
				}
				cbKey = cbitKey / 8;
			}
			else {
				t |= 2;
			}
		}
		CHECK_CONDITION(t != 3, COSE_ERR_INVALID_PARAMETER);

		// Do we need to generate a random key at this point -
		//   This is only true if we both haven't done it and and we have a
		//   recipient to encrypt it.

		if (t == 2) {
			pbKey = (byte *)COSE_CALLOC(cbitKey / 8, 1, context);
			CHECK_CONDITION(pbKey != nullptr, COSE_ERR_OUT_OF_MEMORY);
			cbKey = cbitKey / 8;
			rand_bytes(pbKey, cbKey);
		}
	}

	//  Build protected headers

	const cn_cbor *cbProtected =
		_COSE_encode_protected(&pRecipient->m_encrypt.m_message, perr);
	if (cbProtected == nullptr) {
		goto errorReturn;
	}

	//  Build authenticated data
	size_t cbAuthData = 0;
	if (!_COSE_Encrypt_Build_AAD(&pRecipient->m_encrypt.m_message, &pbAuthData,
			&cbAuthData, "Recipient", perr)) {
		goto errorReturn;
	}

	switch (alg) {
		case COSE_Algorithm_Direct:
#ifdef USE_Direct_HKDF_HMAC_SHA_256
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_512
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
#endif
#ifdef USE_Direct_HKDF_AES_128
		case COSE_Algorithm_Direct_HKDF_AES_128:
#endif
#ifdef USE_Direct_HKDF_AES_256
		case COSE_Algorithm_Direct_HKDF_AES_256:
#endif
#ifdef USE_ECDH_ES_HKDF_256
		case COSE_Algorithm_ECDH_ES_HKDF_256:
#endif
#ifdef USE_ECDH_ES_HKDF_512
		case COSE_Algorithm_ECDH_ES_HKDF_512:
#endif
#ifdef USE_ECDH_SS_HKDF_256
		case COSE_Algorithm_ECDH_SS_HKDF_256:
#endif
#ifdef USE_ECDH_SS_HKDF_512
		case COSE_Algorithm_ECDH_SS_HKDF_512:
#endif
			ptmp = cn_cbor_data_create(
				nullptr, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
			CHECK_CONDITION_CBOR(ptmp != nullptr, cbor_error);
			CHECK_CONDITION_CBOR(
				_COSE_array_replace(&pRecipient->m_encrypt.m_message, ptmp,
					INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA & cbor_error),
				cbor_error);
			ptmp = nullptr;
			break;

#ifdef USE_AES_KW_128
		case COSE_Algorithm_AES_KW_128:
			if (pRecipient->m_pkey != nullptr) {
				cn_cbor *pK =
					cn_cbor_mapget_int(pRecipient->m_pkey->m_cborKey, -1);
				CHECK_CONDITION(pK != nullptr, COSE_ERR_INVALID_PARAMETER);
				if (!AES_KW_Encrypt(pRecipient, pK->v.bytes,
						(int)pK->length * 8, pbContent, (int)cbContent, perr)) {
					goto errorReturn;
				}
			}
			else {
				if (!AES_KW_Encrypt(pRecipient, pbKey, (int)cbKey * 8,
						pbContent, (int)cbContent, perr)) {
					goto errorReturn;
				}
			}
			break;
#endif

#ifdef USE_AES_KW_192
		case COSE_Algorithm_AES_KW_192:
			if (pRecipient->m_pkey != nullptr) {
				cn_cbor *pK =
					cn_cbor_mapget_int(pRecipient->m_pkey->m_cborKey, -1);
				CHECK_CONDITION(pK != nullptr, COSE_ERR_INVALID_PARAMETER);
				if (!AES_KW_Encrypt(pRecipient, pK->v.bytes,
						(int)pK->length * 8, pbContent, (int)cbContent, perr)) {
					goto errorReturn;
				}
			}
			else {
				if (!AES_KW_Encrypt(pRecipient, pbKey, (int)cbKey * 8,
						pbContent, (int)cbContent, perr)) {
					goto errorReturn;
				}
			}
			break;
#endif

#ifdef USE_AES_KW_256
		case COSE_Algorithm_AES_KW_256:
			if (pRecipient->m_pkey != nullptr) {
				cn_cbor *pK =
					cn_cbor_mapget_int(pRecipient->m_pkey->m_cborKey, -1);
				CHECK_CONDITION(pK != nullptr, COSE_ERR_INVALID_PARAMETER);
				if (!AES_KW_Encrypt(pRecipient, pK->v.bytes,
						(int)pK->length * 8, pbContent, (int)cbContent, perr)) {
					goto errorReturn;
				}
			}
			else {
				if (!AES_KW_Encrypt(pRecipient, pbKey, (int)cbKey * 8,
						pbContent, (int)cbContent, perr)) {
					goto errorReturn;
				}
			}
			break;
#endif

#ifdef USE_ECDH_ES_A128KW
		case COSE_Algorithm_ECDH_ES_A128KW:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, false,
					true, COSE_Algorithm_AES_KW_128, nullptr,
					pRecipient->m_pkey, rgbKey, 128, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			if (!AES_KW_Encrypt(
					pRecipient, rgbKey, 128, pbContent, (int)cbContent, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_A192KW
		case COSE_Algorithm_ECDH_ES_A192KW:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, false,
					true, COSE_Algorithm_AES_KW_192, nullptr,
					pRecipient->m_pkey, rgbKey, 192, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			if (!AES_KW_Encrypt(
					pRecipient, rgbKey, 192, pbContent, (int)cbContent, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_A256KW
		case COSE_Algorithm_ECDH_ES_A256KW:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, false,
					true, COSE_Algorithm_AES_KW_256, nullptr,
					pRecipient->m_pkey, rgbKey, 256, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			if (!AES_KW_Encrypt(
					pRecipient, rgbKey, 256, pbContent, (int)cbContent, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_A128KW
		case COSE_Algorithm_ECDH_SS_A128KW:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, true,
					true, COSE_Algorithm_AES_KW_128, pRecipient->m_pkeyStatic,
					pRecipient->m_pkey, rgbKey, 128, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			if (!AES_KW_Encrypt(
					pRecipient, rgbKey, 128, pbContent, (int)cbContent, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_A192KW
		case COSE_Algorithm_ECDH_SS_A192KW:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, true,
					true, COSE_Algorithm_AES_KW_192, pRecipient->m_pkeyStatic,
					pRecipient->m_pkey, rgbKey, 192, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			if (!AES_KW_Encrypt(
					pRecipient, rgbKey, 192, pbContent, (int)cbContent, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_A256KW
		case COSE_Algorithm_ECDH_SS_A256KW:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, true,
					true, COSE_Algorithm_AES_KW_256, pRecipient->m_pkeyStatic,
					pRecipient->m_pkey, rgbKey, 256, 256,
					CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			if (!AES_KW_Encrypt(
					pRecipient, rgbKey, 256, pbContent, (int)cbContent, perr)) {
				goto errorReturn;
			}
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	for (pri = pRecipient->m_encrypt.m_recipientFirst; pri != nullptr;
		 pri = pri->m_recipientNext) {
		if (!_COSE_Recipient_encrypt(pri, pbKey, cbKey, perr)) {
			goto errorReturn;
		}
	}

#if INCLUDE_COUNTERSIGNATURE
	if (pRecipient->m_encrypt.m_message.m_counterSigners != nullptr) {
		if (!_COSE_CounterSign_Sign(&pRecipient->m_encrypt.m_message,
				CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	if (pRecipient->m_encrypt.m_message.m_counterSign1 != NULL) {
		if (!_COSE_CounterSign1_Sign(&pRecipient->m_encrypt.m_message,
				CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif

	//  Figure out the clean up

	fRet = true;
	goto errorReturn;
}

byte *_COSE_RecipientInfo_generateKey(COSE_RecipientInfo *pRecipient,
	int algIn,
	size_t cbitKeySize,
	cose_errback *perr)
{
	int alg;
	const cn_cbor *cn_Alg = _COSE_map_get_int(&pRecipient->m_encrypt.m_message,
		COSE_Header_Algorithm, COSE_BOTH, perr);
	byte *pbContext = nullptr;
	byte *pb = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pRecipient->m_encrypt.m_message.m_allocContext;
#endif
	const cn_cbor *pK;
	byte *pbSecret = nullptr;

	CHECK_CONDITION(cn_Alg != nullptr, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(
		(cn_Alg->type == CN_CBOR_UINT) || (cn_Alg->type == CN_CBOR_INT),
		COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn_Alg->v.uint;

	_COSE_encode_protected(&pRecipient->m_encrypt.m_message, perr);

	pb = (byte *)COSE_CALLOC(cbitKeySize / 8, 1, context);
	CHECK_CONDITION(pb != nullptr, COSE_ERR_OUT_OF_MEMORY);

	switch (alg) {
		case COSE_Algorithm_Direct:
			CHECK_CONDITION(
				pRecipient->m_pkey != nullptr, COSE_ERR_INVALID_PARAMETER);
			pK = cn_cbor_mapget_int(pRecipient->m_pkey->m_cborKey, -1);
			CHECK_CONDITION((pK != nullptr) && (pK->type == CN_CBOR_BYTES),
				COSE_ERR_INVALID_PARAMETER);
			CHECK_CONDITION((size_t)pK->length == cbitKeySize / 8,
				COSE_ERR_INVALID_PARAMETER);
			memcpy(pb, pK->v.bytes, cbitKeySize / 8);
			break;

#ifdef USE_Direct_HKDF_HMAC_SHA_256
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, false, false,
					true, algIn, pRecipient->m_pkey, nullptr, pb, cbitKeySize,
					256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_Direct_HKDF_HMAC_SHA_512
		case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, false, false,
					true, algIn, pRecipient->m_pkey, nullptr, pb, cbitKeySize,
					512, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_Direct_HKDF_AES_128
		case COSE_Algorithm_Direct_HKDF_AES_128:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, false, false, false,
					true, algIn, pRecipient->m_pkey, nullptr, pb, cbitKeySize,
					128, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_Direct_HKDF_AES_256
		case COSE_Algorithm_Direct_HKDF_AES_256:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, false, false, false,
					true, algIn, pRecipient->m_pkey, nullptr, pb, cbitKeySize,
					256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_HKDF_256
		case COSE_Algorithm_ECDH_ES_HKDF_256:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, false,
					true, algIn, nullptr, pRecipient->m_pkey, pb, cbitKeySize,
					256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_ES_HKDF_512
		case COSE_Algorithm_ECDH_ES_HKDF_512:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, false,
					true, algIn, nullptr, pRecipient->m_pkey, pb, cbitKeySize,
					512, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_HKDF_256
		case COSE_Algorithm_ECDH_SS_HKDF_256:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, true,
					true, algIn, pRecipient->m_pkeyStatic, pRecipient->m_pkey,
					pb, cbitKeySize, 256, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_ECDH_SS_HKDF_512
		case COSE_Algorithm_ECDH_SS_HKDF_512:
			if (!HKDF_X(&pRecipient->m_encrypt.m_message, true, true, true,
					true, algIn, pRecipient->m_pkeyStatic, pRecipient->m_pkey,
					pb, cbitKeySize, 512, CBOR_CONTEXT_PARAM_COMMA perr)) {
				goto errorReturn;
			}
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	if (pbSecret != nullptr) {
		COSE_FREE(pbSecret, context);
	}
	if (pbContext != nullptr) {
		COSE_FREE(pbContext, context);
	}
	return pb;

errorReturn:

	if (pbSecret != nullptr) {
		COSE_FREE(pbSecret, context);
	}
	if (pbContext != nullptr) {
		COSE_FREE(pbContext, context);
	}
	if (pb != nullptr) {
		COSE_FREE(pb, context);
	}
	return nullptr;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
bool COSE_Recipient_SetKey_secret(HCOSE_RECIPIENT hRecipient,
	const byte *rgbKey,
	int cbKey,
	const byte *rgbKid,
	int cbKid,
	cose_errback *perr)
{
	COSE_RecipientInfo *p;
	cn_cbor *cn_Temp = nullptr;
	cn_cbor *cnTemp = nullptr;
	cn_cbor_errback cbor_error;
	byte *pbTemp = nullptr;
	byte *pbKey = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = nullptr;
#endif
	HCOSE_KEY hKey = nullptr;

	if (false) {
	errorReturn:
		if (hKey != nullptr) {
			COSE_KEY_Free(hKey);
		}
		if (cn_Temp != nullptr) {
			CN_CBOR_FREE(cn_Temp, context);
		}
		if (cnTemp != nullptr) {
			CN_CBOR_FREE(cnTemp, context);
		}
		if (pbTemp != nullptr) {
			COSE_FREE(pbTemp, context);
		}
		if (pbKey != nullptr) {
			COSE_FREE(pbKey, context);
		}
		return false;
	}

	CHECK_CONDITION(
		IsValidRecipientHandle(hRecipient), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(rgbKey != nullptr, COSE_ERR_INVALID_PARAMETER);

	p = (COSE_RecipientInfo *)hRecipient;

#ifdef USE_CBOR_CONTEXT
	context = &p->m_encrypt.m_message.m_allocContext;
#endif

	cn_cbor *cnAlg = _COSE_map_get_int(
		&p->m_encrypt.m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cnAlg != nullptr) {
		CHECK_CONDITION(cnAlg->type == CN_CBOR_INT &&
							cnAlg->v.sint == COSE_Algorithm_Direct,
			COSE_ERR_INVALID_PARAMETER);
	}
	else {
		cn_Temp = cn_cbor_int_create(
			COSE_Algorithm_Direct, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cn_Temp != nullptr, cbor_error);
		if (!COSE_Recipient_map_put_int(hRecipient, COSE_Header_Algorithm,
				cn_Temp, COSE_UNPROTECT_ONLY, perr)) {
			goto errorReturn;
		}
		cn_Temp = nullptr;
	}

	if (cbKid > 0) {
		pbTemp = (byte *)COSE_CALLOC(cbKid, 1, context);
		CHECK_CONDITION(pbTemp != nullptr, COSE_ERR_OUT_OF_MEMORY);

		memcpy(pbTemp, rgbKid, cbKid);
		cnTemp = cn_cbor_data_create(
			pbTemp, cbKid, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cnTemp != nullptr, cbor_error);
		pbTemp = nullptr;

		if (!COSE_Recipient_map_put_int(hRecipient, COSE_Header_KID, cnTemp,
				COSE_UNPROTECT_ONLY, perr)) {
			goto errorReturn;
		}
	}

	pbKey = (byte *)COSE_CALLOC(cbKey, 1, context);
	CHECK_CONDITION(pbKey != nullptr, COSE_ERR_OUT_OF_MEMORY);

	memcpy(pbKey, rgbKey, cbKey);

	cn_Temp = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cn_Temp != nullptr, cbor_error);

	cnTemp = cn_cbor_int_create(4, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnTemp != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_mapput_int(cn_Temp, COSE_Key_Type, cnTemp,
							 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
		cbor_error);
	cnTemp = nullptr;

	cnTemp = cn_cbor_data_create(
		pbKey, cbKey, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnTemp != nullptr, cbor_error);
	pbKey = nullptr;
	CHECK_CONDITION_CBOR(cn_cbor_mapput_int(cn_Temp, -1, cnTemp,
							 CBOR_CONTEXT_PARAM_COMMA & cbor_error),
		cbor_error);
	cnTemp = nullptr;

	hKey = COSE_KEY_FromCbor(cn_Temp, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(hKey != nullptr, COSE_ERR_OUT_OF_MEMORY);

	if (!COSE_Recipient_SetKey2(hRecipient, hKey, perr)) {
		goto errorReturn;
	}
	cn_Temp = nullptr;

	return true;
}

bool COSE_Recipient_SetKey(HCOSE_RECIPIENT h,
	const cn_cbor *pKey,
	cose_errback *perr)
{
	HCOSE_KEY hkey = nullptr;

	if (false) {
	errorReturn:
		if (hkey != nullptr) {
			COSE_KEY_Free(hkey);
		}
		return false;
	}

	CHECK_CONDITION(IsValidRecipientHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pKey != nullptr, COSE_ERR_INVALID_PARAMETER);

	COSE_RecipientInfo *p = (COSE_RecipientInfo *)h;

#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &p->m_encrypt.m_message.m_allocContext;
#endif

	hkey = COSE_KEY_FromCbor((cn_cbor *)pKey, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(hkey != nullptr, COSE_ERR_OUT_OF_MEMORY);
	if (!COSE_Recipient_SetKey2(h, hkey, perr)) {
		goto errorReturn;
	}
	COSE_KEY_Free(hkey);
	return true;
}

bool COSE_Recipient_SetKey2(HCOSE_RECIPIENT h,
	HCOSE_KEY hKey,
	cose_errback *perr)
{
	COSE_RecipientInfo *p;

	CHECK_CONDITION(IsValidRecipientHandle(h), COSE_ERR_INVALID_HANDLE);

	p = (COSE_RecipientInfo *)h;
	if (p->m_pkey != nullptr) {
		COSE_KEY_Free((HCOSE_KEY)p->m_pkey);
	}

	p->m_pkey = (COSE_KEY *)hKey;
	if (p->m_pkey != nullptr) {
		p->m_pkey->m_refCount += 1;
	}

	return true;

errorReturn:
	return false;
}

/*!
 * @brief Set the senders static key for ECDH key agreement algorithms
 *
 * Set the Static private key to be used in computing ECDH key agreement
 * operation.
 *
 * Private portion of the key is not zeroed when the recipient object is
 * released.
 *
 * @param h  Handle to the recipient object
 * @param pKey pointer to COSE key structure containing the private key
 * @param destination 0 - set nothing, 1 - set spk_kid, 2 - set spk
 * @param perr location for return of error code
 * @return true on success
 */

bool COSE_Recipient_SetSenderKey(HCOSE_RECIPIENT h,
	const cn_cbor *pKey,
	int destination,
	cose_errback *perr)
{
	bool fRet = false;
	HCOSE_KEY coseKey = nullptr;

	if (false) {
	errorReturn:
		if (coseKey != nullptr) {
			COSE_KEY_Free(coseKey);
		}
		return fRet;
	}

	CHECK_CONDITION(IsValidRecipientHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pKey != nullptr, COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	COSE_RecipientInfo *pRecipient = (COSE_RecipientInfo *)h;
	cn_cbor_context *context = &pRecipient->m_encrypt.m_message.m_allocContext;
#endif

	coseKey = COSE_KEY_FromCbor((cn_cbor *)pKey, CBOR_CONTEXT_PARAM_COMMA perr);
	CHECK_CONDITION(coseKey != nullptr, COSE_ERR_OUT_OF_MEMORY);

	fRet = COSE_Recipient_SetSenderKey2(h, coseKey, destination, perr);
	goto errorReturn;
}

bool COSE_Recipient_SetSenderKey2(HCOSE_RECIPIENT h,
	HCOSE_KEY hKey,
	int destination,
	cose_errback *perr)
{
	COSE_RecipientInfo *p;
	bool f = false;
	cn_cbor *cn;
	cn_cbor *cn2 = nullptr;
	cn_cbor *cn3 = nullptr;
	cn_cbor_errback cbor_err;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = nullptr;
#endif

	if (false) {
	errorReturn:
		if (cn2 != nullptr) {
			CN_CBOR_FREE(cn2, context);
		}
		if (cn3 != nullptr) {
			CN_CBOR_FREE(cn3, context);
		}
		return f;
	}

	CHECK_CONDITION(IsValidRecipientHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidKeyHandle(hKey), COSE_ERR_INVALID_PARAMETER);

	p = (COSE_RecipientInfo *)h;
	COSE_KEY *pKey = (COSE_KEY *)hKey;

#ifdef USE_CBOR_CONTEXT
	context = &p->m_encrypt.m_message.m_allocContext;
#endif

	switch (destination) {
		case 0:
			break;

		case COSE_PROTECT_ONLY:
			cn = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_ID);
			CHECK_CONDITION(cn != nullptr, COSE_ERR_INVALID_PARAMETER);
			cn2 = cn_cbor_clone(cn, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
			CHECK_CONDITION_CBOR(cn2 != nullptr, cbor_err);
			CHECK_CONDITION(
				_COSE_map_put(&p->m_encrypt.m_message, COSE_Header_ECDH_SPK_KID,
					cn2, COSE_UNPROTECT_ONLY, perr),
				perr->err);
			cn2 = nullptr;
			break;

		case COSE_UNPROTECT_ONLY:
			if (pKey->m_cborKey == nullptr) {
#ifdef COSE_C_USE_OPENSSL
				pKey->m_cborKey = EVP_ToCBOR(pKey->m_opensslKey, true,
#ifdef USE_CBOR_CONTEXT
					&pKey->m_allocContext,
#endif
					perr);
				if (pKey->m_cborKey == nullptr) {
					return false;
				}
#else
				return false;
#endif
			}
			cn2 = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA & cbor_err);
			CHECK_CONDITION_CBOR(cn2 != nullptr, cbor_err);
			cn = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_Type);
			CHECK_CONDITION(cn != nullptr, COSE_ERR_INVALID_PARAMETER);
			cn3 = cn_cbor_clone(cn, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
			CHECK_CONDITION_CBOR(cn3 != nullptr, cbor_err);
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(cn2, COSE_Key_Type, cn3,
									 CBOR_CONTEXT_PARAM_COMMA & cbor_err),
				cbor_err);
			cn3 = nullptr;
			cn = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC2_Curve);
			cn3 = cn_cbor_clone(cn, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
			CHECK_CONDITION_CBOR(cn3 != nullptr, cbor_err);
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(cn2, COSE_Key_EC2_Curve,
									 cn3, CBOR_CONTEXT_PARAM_COMMA & cbor_err),
				cbor_err);
			cn3 = nullptr;
			cn = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC2_X);
			cn3 = cn_cbor_clone(cn, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
			CHECK_CONDITION_CBOR(cn3 != nullptr, cbor_err);
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(cn2, COSE_Key_EC2_X, cn3,
									 CBOR_CONTEXT_PARAM_COMMA & cbor_err),
				cbor_err);
			cn3 = nullptr;
			cn = cn_cbor_mapget_int(pKey->m_cborKey, COSE_Key_EC2_Y);
			cn3 = cn_cbor_clone(cn, CBOR_CONTEXT_PARAM_COMMA & cbor_err);
			CHECK_CONDITION_CBOR(cn3 != nullptr, cbor_err);
			CHECK_CONDITION_CBOR(cn_cbor_mapput_int(cn2, COSE_Key_EC2_Y, cn3,
									 CBOR_CONTEXT_PARAM_COMMA & cbor_err),
				cbor_err);
			cn3 = nullptr;
			CHECK_CONDITION(
				_COSE_map_put(&p->m_encrypt.m_message, COSE_Header_ECDH_SPK,
					cn2, COSE_UNPROTECT_ONLY, perr),
				perr->err);
			cn2 = nullptr;
			break;

		case COSE_DONT_SEND:
			break;

		default:
			FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
	}

	if (p->m_pkeyStatic != nullptr) {
		COSE_KEY_Free((HCOSE_KEY)p->m_pkeyStatic);
	}
	p->m_pkeyStatic = pKey;
	pKey->m_refCount += 1;

	f = true;
	goto errorReturn;
}

/*!
 * @brief Set the application external data for authentication
 *
 * Recipient data objects support the authentication of external application
 * supplied data.  This function is provided to supply that data to the library.
 *
 * The external data is not copied, nor will be it freed when the handle is
 * released.
 *
 * @param hcose  Handle for the COSE recipient data object
 * @param pbEternalData  point to the external data
 * @param cbExternalData size of the external data
 * @param perr  location to return errors
 * @return result of the operation.
 */

bool COSE_Recipient_SetExternal(HCOSE_RECIPIENT hcose,
	const byte *pbExternalData,
	size_t cbExternalData,
	cose_errback *perr)
{
	if (!IsValidRecipientHandle(hcose)) {
		if (perr != nullptr) {
			perr->err = COSE_ERR_INVALID_HANDLE;
		}
		return false;
	}

	return _COSE_SetExternal(
		&((COSE_RecipientInfo *)hcose)->m_encrypt.m_message, pbExternalData,
		cbExternalData, perr);
}

bool COSE_Recipient_map_put_int(HCOSE_RECIPIENT h,
	int key,
	cn_cbor *value,
	int flags,
	cose_errback *perr)
{
	CHECK_CONDITION(IsValidRecipientHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != nullptr, COSE_ERR_INVALID_PARAMETER);

	if (!_COSE_map_put(&((COSE_RecipientInfo *)h)->m_encrypt.m_message, key,
			value, flags, perr)) {
		return false;
	}

	if (key == COSE_Header_Algorithm) {
		if (value->type == CN_CBOR_INT) {
			switch (value->v.sint) {
				case COSE_Algorithm_Direct:
#ifdef USE_Direct_HKDF_AES_128
				case COSE_Algorithm_Direct_HKDF_AES_128:
#endif
#ifdef USE_Direct_HKDF_AES_256
				case COSE_Algorithm_Direct_HKDF_AES_256:
#endif
#ifdef USE_Direct_HKDF_HMAC_SHA_256
				case COSE_Algorithm_Direct_HKDF_HMAC_SHA_256:
#endif
#ifdef USE_Direct_HKDF_HMAC_SHA_512
				case COSE_Algorithm_Direct_HKDF_HMAC_SHA_512:
#endif
#ifdef USE_ECDH_ES_HKDF_256
				case COSE_Algorithm_ECDH_ES_HKDF_256:
#endif
#ifdef USE_ECDH_ES_HKDF_512
				case COSE_Algorithm_ECDH_ES_HKDF_512:
#endif
#ifdef USE_ECDH_SS_HKDF_256
				case COSE_Algorithm_ECDH_SS_HKDF_256:
#endif
#ifdef USE_ECDH_SS_HKDF_512
				case COSE_Algorithm_ECDH_SS_HKDF_512:
#endif
					((COSE_RecipientInfo *)h)
						->m_encrypt.m_message.m_flags = (cose_init_flags)(
						((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags |
						COSE_INIT_FLAGS_DETACHED_CONTENT);
					break;

				default:
					((COSE_RecipientInfo *)h)
						->m_encrypt.m_message.m_flags = (cose_init_flags)(
						((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags &
						~COSE_INIT_FLAGS_DETACHED_CONTENT);
					break;
			}
		}
		else {
			((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags =
				(cose_init_flags)(
					((COSE_RecipientInfo *)h)->m_encrypt.m_message.m_flags &
					~COSE_INIT_FLAGS_DETACHED_CONTENT);
		}
	}

	return true;

errorReturn:
	return false;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0 || INCLUDE_MAC || INCLUDE_MAC0
static bool BuildContextBytes(COSE *pcose,
	int algID,
	size_t cbitKey,
	byte **ppbContext,
	size_t *pcbContext,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	cn_cbor *pArray;
	cn_cbor_errback cbor_error;
	bool fReturn = false;
	cn_cbor *cnT = nullptr;
	cn_cbor *cnArrayT = nullptr;
	cn_cbor *cnParam;
	byte *pbContext = nullptr;

	if (false) {
	errorReturn:
		fReturn = false;

	returnHere:
		if (pbContext != nullptr) {
			COSE_FREE(pbContext, context);
		}
		if (pArray != nullptr) {
			CN_CBOR_FREE(pArray, context);
		}
		if (cnArrayT != nullptr) {
			CN_CBOR_FREE(cnArrayT, context);
		}
		if (cnT != nullptr) {
			CN_CBOR_FREE(cnT, context);
		}
		return fReturn;
	}

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(pArray != nullptr, cbor_error);

	cnT = cn_cbor_int_create(algID, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cnT, &cbor_error), cbor_error);
	cnT = nullptr;

	cnArrayT = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnArrayT != nullptr, cbor_error);

	cnParam = _COSE_map_get_int(pcose, COSE_Header_KDF_U_name, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cnT = cn_cbor_null_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;
	cnParam = nullptr;

	cnParam =
		_COSE_map_get_int(pcose, COSE_Header_KDF_U_nonce, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cnT = cn_cbor_null_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;
	cnParam = nullptr;

	cnParam =
		_COSE_map_get_int(pcose, COSE_Header_KDF_U_other, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cnT = cn_cbor_null_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;
	cnParam = nullptr;

	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cnArrayT, &cbor_error), cbor_error);
	cnArrayT = nullptr;

	cnArrayT = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnArrayT != nullptr, cbor_error);

	cnParam = _COSE_map_get_int(pcose, COSE_Header_KDF_V_name, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cnT = cn_cbor_null_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;
	cnParam = nullptr;

	cnParam =
		_COSE_map_get_int(pcose, COSE_Header_KDF_V_nonce, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cnT = cn_cbor_null_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;
	cnParam = nullptr;

	cnParam =
		_COSE_map_get_int(pcose, COSE_Header_KDF_V_other, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		cnT = cn_cbor_null_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;
	cnParam = nullptr;

	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cnArrayT, &cbor_error), cbor_error);
	cnArrayT = nullptr;

	cnArrayT = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnArrayT != nullptr, cbor_error);

	cnT = cn_cbor_int_create(cbitKey, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
	cnT = nullptr;

	cnParam = _COSE_arrayget_int(pcose, INDEX_PROTECTED);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
		CHECK_CONDITION_CBOR(
			cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
		cnT = nullptr;
		cnParam = nullptr;
	}

	cnParam =
		_COSE_map_get_int(pcose, COSE_Header_KDF_PUB_other, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
		CHECK_CONDITION_CBOR(
			cn_cbor_array_append(cnArrayT, cnT, &cbor_error), cbor_error);
		cnT = nullptr;
		cnParam = nullptr;
	}

	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pArray, cnArrayT, &cbor_error), cbor_error);
	cnArrayT = nullptr;

	cnParam = _COSE_map_get_int(pcose, COSE_Header_KDF_PRIV, COSE_BOTH, perr);
	if (cnParam != nullptr) {
		cnT = cn_cbor_clone(cnParam, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(cnT != nullptr, cbor_error);
		CHECK_CONDITION_CBOR(
			cn_cbor_array_append(pArray, cnT, &cbor_error), cbor_error);
		cnT = nullptr;
		cnParam = nullptr;
	}

	size_t cbContext = cn_cbor_encode_size(pArray);
	CHECK_CONDITION(cbContext > 0, COSE_ERR_CBOR);
	pbContext = (byte *)COSE_CALLOC(cbContext, 1, context);
	CHECK_CONDITION(pbContext != nullptr, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION(cn_cbor_encoder_write(pbContext, 0, cbContext, pArray) ==
						(ssize_t)cbContext,
		COSE_ERR_CBOR);

	*ppbContext = pbContext;
	*pcbContext = cbContext;
	pbContext = nullptr;
	fReturn = true;

	goto returnHere;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
/*! brief Retrieve header parameter from a recipient structure
 *
 * Retrieve a header parameter from the message.
 * Retrieved object is the same as the one in the message - do not delete it
 *
 * @param[in]	h	Handle of recipient object
 * @param[in]    key	Key to look for
 * @param[in]	flags	What buckets should we look for the message
 * @param[out]	perror	Location to return error codes
 * @return	Object which is found or nullptr
 */

cn_cbor *COSE_Recipient_map_get_int(HCOSE_RECIPIENT h,
	int key,
	int flags,
	cose_errback *perror)
{
	if (!IsValidRecipientHandle(h)) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_INVALID_HANDLE;
		}
		return nullptr;
	}

	return _COSE_map_get_int(
		&((COSE_RecipientInfo *)h)->m_encrypt.m_message, key, flags, perror);
}

HCOSE_RECIPIENT COSE_Recipient_GetRecipient(HCOSE_RECIPIENT cose,
	int iRecipient,
	cose_errback *perr)
{
	int i;
	COSE_RecipientInfo *p = nullptr;

	CHECK_CONDITION(IsValidRecipientHandle(cose), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(iRecipient >= 0, COSE_ERR_INVALID_PARAMETER);

	p = ((COSE_RecipientInfo *)cose)->m_encrypt.m_recipientFirst;
	for (i = 0; i < iRecipient; i++) {
		CHECK_CONDITION(p != nullptr, COSE_ERR_INVALID_PARAMETER);
		p = p->m_recipientNext;
	}
	if (p != nullptr) {
		p->m_encrypt.m_message.m_refCount++;
	}

errorReturn:
	return (HCOSE_RECIPIENT)p;
}

bool COSE_Recipient_AddRecipient(HCOSE_RECIPIENT hEnc,
	HCOSE_RECIPIENT hRecip,
	cose_errback *perr)
{
	COSE_RecipientInfo *pRecip;
	COSE_Enveloped *pEncrypt;
	cn_cbor *pRecipients = nullptr;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context;
#endif
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidRecipientHandle(hEnc), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidRecipientHandle(hRecip), COSE_ERR_INVALID_HANDLE);

	pEncrypt = &((COSE_RecipientInfo *)hEnc)->m_encrypt;
	pRecip = (COSE_RecipientInfo *)hRecip;

#ifdef USE_CBOR_CONTEXT
	context = &pEncrypt->m_message.m_allocContext;
#endif	// USE_CBOR_CONTEXT

	pRecipients = _COSE_arrayget_int(&pEncrypt->m_message, INDEX_RECIPIENTS);
	if (pRecipients == nullptr) {
		pRecipients =
			cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
		CHECK_CONDITION_CBOR(pRecipients != nullptr, cbor_error);

		if (!_COSE_array_replace(&pEncrypt->m_message, pRecipients,
				INDEX_RECIPIENTS, CBOR_CONTEXT_PARAM_COMMA & cbor_error)) {
			CN_CBOR_FREE(pRecipients, context);
			if (perr != nullptr) {
				perr->err = _MapFromCBOR(cbor_error);
			}
			goto errorReturn;
		}
	}

	CHECK_CONDITION_CBOR(cn_cbor_array_append(pRecipients,
							 pRecip->m_encrypt.m_message.m_cbor, &cbor_error),
		cbor_error);

	pRecip->m_recipientNext = pEncrypt->m_recipientFirst;
	pEncrypt->m_recipientFirst = pRecip;
	pRecip->m_encrypt.m_message.m_refCount++;

	return true;

errorReturn:
	return false;
}

#endif
