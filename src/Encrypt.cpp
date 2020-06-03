/** \file Encrypt.c
 * Contains implementation of the functions related to HCOSE_ENVELOPED handle
 * objects.
 */

#include <stdlib.h>
#ifdef __MBED__
#include <stddef.h>
#include <string.h>
#else
#include <memory.h>
#endif
#include <stdio.h>
#include <assert.h>

#include "cose/cose.h"
#include "cose_int.h"
#include "cose/cose_configure.h"
#include "cose_crypto.h"

#if INCLUDE_ENCRYPT || INCLUDE_MAC
COSE *EnvelopedRoot = nullptr;
#endif

#if INCLUDE_ENCRYPT
/*! \private
 * @brief Test if a HCOSE_ENVELOPED handle is valid
 *
 *  Internal function to test if a enveloped message handle is valid.
 *  This will start returning invalid results and cause the code to
 *  crash if handles are not released before the memory that underlies them
 *  is deallocated.  This is an issue of a block allocator is used since
 *  in that case it is common to allocate memory but never to de-allocate it
 *  and just do that in a single big block.
 *
 *  @param h handle to be validated
 *  @returns result of check
 */

bool IsValidEnvelopedHandle(HCOSE_ENVELOPED h)
{
	COSE_Enveloped *p = (COSE_Enveloped *)h;
	return _COSE_IsInList(EnvelopedRoot, (COSE *)p);
}

/*!
 * @brief Allocate and initialize an object for creation of an Enveloped message
 * object
 *
 * Allocate and initialize the object used to create a COSE Enveloped message
 * object. Supported flags are: COSE_INIT_FLAG_DETACHED_CONTENT - content is not
 * part of the message COSE_INIT_NO_CBOR_FLAG - Do not emit the leading CBOR tag
 * on the message.
 *
 *  See the notes on the memory model for the use of the context variable.
 *  Applications need to free the returned handle before deallocating the
 *  memory block that it was wrapped in for correct handle checking.
 *
 * @param flags Set of initialization flags from the COSE_INIT_FLAGS enum
 * @param context CN_CBOR context allocator struture
 * @param perr Location to return error specific information
 * @returns handle to the newly allocated object
 */
HCOSE_ENVELOPED COSE_Enveloped_Init(COSE_INIT_FLAGS flags,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	COSE_Enveloped *pobj =
		(COSE_Enveloped *)COSE_CALLOC(1, sizeof(COSE_Enveloped), context);
	CHECK_CONDITION(pobj != nullptr, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(flags, &pobj->m_message, COSE_enveloped_object,
			CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Enveloped_Release(pobj);
		COSE_FREE(pobj, context);
		return nullptr;
	}

	_COSE_InsertInList(&EnvelopedRoot, &pobj->m_message);

	return (HCOSE_ENVELOPED)pobj;

errorReturn:
	return nullptr;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
HCOSE_ENVELOPED _COSE_Enveloped_Init_From_Object(cn_cbor *cbor,
	COSE_Enveloped *pIn,
	CBOR_CONTEXT_COMMA cose_errback *perr)
{
	COSE_Enveloped *pobj = pIn;
	cn_cbor *pRecipients = nullptr;
	cose_errback error = {COSE_ERR_NONE};
	if (perr == nullptr) {
		perr = &error;
	}

	if (pobj == nullptr) {
		pobj =
			(COSE_Enveloped *)COSE_CALLOC(1, sizeof(COSE_Enveloped), context);
	}
	if (pobj == nullptr) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pobj != nullptr) {
			pobj->m_message.m_ownMsg = false;
		}
		if (pIn == nullptr && pobj != nullptr) {
			_COSE_Enveloped_Release(pobj);
			COSE_FREE(pobj, context);
		}
		return nullptr;
	}

	if (!_COSE_Init_From_Object(
			&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	pRecipients = _COSE_arrayget_int(&pobj->m_message, INDEX_RECIPIENTS);
	if (pRecipients != nullptr) {
		CHECK_CONDITION(
			pRecipients->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

		pRecipients = pRecipients->first_child;
		while (pRecipients != nullptr) {
			COSE_RecipientInfo *pInfo = _COSE_Recipient_Init_From_Object(
				pRecipients, CBOR_CONTEXT_PARAM_COMMA perr);
			CHECK_CONDITION(pInfo != nullptr, COSE_ERR_OUT_OF_MEMORY);

			pInfo->m_recipientNext = pobj->m_recipientFirst;
			pobj->m_recipientFirst = pInfo;
			pRecipients = pRecipients->next;
		}
	}

	if (pIn == nullptr) {
		_COSE_InsertInList(&EnvelopedRoot, &pobj->m_message);
	}

	return (HCOSE_ENVELOPED)pobj;
}
#endif

#if INCLUDE_ENCRYPT
bool COSE_Enveloped_Free(HCOSE_ENVELOPED h)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context;
#endif
	COSE_Enveloped *p = (COSE_Enveloped *)h;

	if (!IsValidEnvelopedHandle(h)) {
		return false;
	}

	if (p->m_message.m_refCount > 1) {
		p->m_message.m_refCount--;
		return true;
	}

#ifdef USE_CBOR_CONTEXT
	context = &((COSE_Enveloped *)h)->m_message.m_allocContext;
#endif

	_COSE_RemoveFromList(&EnvelopedRoot, &p->m_message);

	_COSE_Enveloped_Release((COSE_Enveloped *)h);

	COSE_FREE((COSE_Enveloped *)h, context);

	return true;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_MAC
void _COSE_Enveloped_Release(COSE_Enveloped *p)
{
	COSE_RecipientInfo *pRecipient1;
	COSE_RecipientInfo *pRecipient2;

	if (p->pbContent != nullptr) {
		COSE_FREE((void *)p->pbContent, &p->m_message.m_allocContext);
	}
	//	if (p->pbIV != nullptr) COSE_FREE(p->pbIV,
	//&p->m_message.m_allocContext);

	for (pRecipient1 = p->m_recipientFirst; pRecipient1 != nullptr;
		 pRecipient1 = pRecipient2) {
		pRecipient2 = pRecipient1->m_recipientNext;
		COSE_Recipient_Free((HCOSE_RECIPIENT)pRecipient1);
	}

	_COSE_Release(&p->m_message);
}
#endif

#if INCLUDE_ENCRYPT
bool COSE_Enveloped_decrypt(HCOSE_ENVELOPED h,
	HCOSE_RECIPIENT hRecip,
	cose_errback *perr)
{
	COSE_Enveloped *pcose = (COSE_Enveloped *)h;
	COSE_RecipientInfo *pRecip = (COSE_RecipientInfo *)hRecip;
	bool f = false;

	CHECK_CONDITION(IsValidEnvelopedHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidRecipientHandle(hRecip), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		pcose->m_recipientFirst != nullptr, COSE_ERR_INVALID_PARAMETER);

	f = _COSE_Enveloped_decrypt(pcose, pRecip, nullptr, 0, "Encrypt", perr);

errorReturn:
	return f;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0
bool _COSE_Enveloped_decrypt(COSE_Enveloped *pcose,
	COSE_RecipientInfo *pRecip,
	const byte *pbKeyIn,
	size_t cbKeyIn,
	const char *szContext,
	cose_errback *perr)
{
	int alg;
	const cn_cbor *cn = nullptr;
	byte *pbKeyNew = nullptr;
	const byte *pbKey = nullptr;
	size_t cbitKey = 0;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context;
#endif
	byte *pbAuthData = nullptr;
	size_t cbAuthData;

#ifdef USE_CBOR_CONTEXT
	context = &pcose->m_message.m_allocContext;
#endif

	CHECK_CONDITION(
		!((pRecip != nullptr) && (pbKeyIn != nullptr)), COSE_ERR_INTERNAL);

	cn = _COSE_map_get_int(
		&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == nullptr) {
	error:
	errorReturn:
		if (pbAuthData != nullptr) {
			COSE_FREE(pbAuthData, context);
		}
		if (pbKeyNew != nullptr) {
			memset(pbKeyNew, 0xff, cbitKey / 8);
			COSE_FREE(pbKeyNew, context);
		}
		return false;
	}
	CHECK_CONDITION((cn->type == CN_CBOR_UINT) || (cn->type == CN_CBOR_INT),
		COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn->v.uint;

	switch (alg) {
#ifdef USE_AES_CCM_16_64_128
		case COSE_Algorithm_AES_CCM_16_64_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_16_128_128
		case COSE_Algorithm_AES_CCM_16_128_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_64_64_128
		case COSE_Algorithm_AES_CCM_64_64_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_64_128_128
		case COSE_Algorithm_AES_CCM_64_128_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_64_64_256
		case COSE_Algorithm_AES_CCM_64_64_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_CCM_16_128_256
		case COSE_Algorithm_AES_CCM_16_128_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_CCM_64_128_256
		case COSE_Algorithm_AES_CCM_64_128_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_CCM_16_64_256
		case COSE_Algorithm_AES_CCM_16_64_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_GCM_128
		case COSE_Algorithm_AES_GCM_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_GCM_192
		case COSE_Algorithm_AES_GCM_192:
			cbitKey = 192;
			break;
#endif

#ifdef USE_AES_GCM_256
		case COSE_Algorithm_AES_GCM_256:
			cbitKey = 256;
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			break;
	}

	//
	//  We are doing the enveloped item - so look for the passed in recipient
	//

	if (pbKeyIn != nullptr) {
		CHECK_CONDITION(cbKeyIn == cbitKey / 8, COSE_ERR_INVALID_PARAMETER);
		pbKey = pbKeyIn;
	}
#ifdef INCLUDE_ENCRYPT
	else {
		//  Allocate the key if we have not already done so

		if (pbKeyNew == nullptr) {
			pbKeyNew =
				static_cast<byte *>(COSE_CALLOC(cbitKey / 8, 1, context));
			CHECK_CONDITION(pbKeyNew != nullptr, COSE_ERR_OUT_OF_MEMORY);
			pbKey = pbKeyNew;
		}

		//  If there is a recipient - ask it for the key

		if (pRecip != nullptr) {
			COSE_RecipientInfo *pRecipX = nullptr;
			cose_errback errorLocal = {COSE_ERR_NONE};
			cose_error errorFound = COSE_ERR_NONE;

			for (pRecipX = pcose->m_recipientFirst; pRecipX != nullptr;
				 pRecipX = pRecipX->m_recipientNext) {
				if (pRecipX == pRecip) {
					if (!_COSE_Recipient_decrypt(
							pRecipX, pRecip, alg, cbitKey, pbKeyNew, perr)) {
						goto errorReturn;
					}
					break;
				}
				else if (pRecipX->m_encrypt.m_recipientFirst != nullptr) {
					if (_COSE_Recipient_decrypt(pRecipX, pRecip, alg, cbitKey,
							pbKeyNew, &errorLocal)) {
						break;
					}
				}
				errorFound = errorLocal.err;
			}
			if (errorFound != 0) {
				perr->err = errorFound;
				goto errorReturn;
			}
			CHECK_CONDITION(pRecipX != nullptr, COSE_ERR_NO_RECIPIENT_FOUND);
		}
		else {
			for (pRecip = pcose->m_recipientFirst; pRecip != nullptr;
				 pRecip = pRecip->m_recipientNext) {
				if (_COSE_Recipient_decrypt(
						pRecip, nullptr, alg, cbitKey, pbKeyNew, perr)) {
					break;
				}
			}
			CHECK_CONDITION(pRecip != nullptr, COSE_ERR_NO_RECIPIENT_FOUND);
		}
	}
#endif	// INCLUDE_ENCRYPT

	//  Build authenticated data

	if (!_COSE_Encrypt_Build_AAD(
			&pcose->m_message, &pbAuthData, &cbAuthData, szContext, perr)) {
		goto errorReturn;
	}

	cn = _COSE_arrayget_int(&pcose->m_message, INDEX_BODY);
	CHECK_CONDITION(cn != nullptr, COSE_ERR_INVALID_PARAMETER);

	switch (alg) {
#ifdef USE_AES_CCM_16_64_128
		case COSE_Algorithm_AES_CCM_16_64_128:
			if (!AES_CCM_Decrypt(pcose, 64, 16, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_16_64_256
		case COSE_Algorithm_AES_CCM_16_64_256:
			if (!AES_CCM_Decrypt(pcose, 64, 16, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_16_128_128
		case COSE_Algorithm_AES_CCM_16_128_128:
			if (!AES_CCM_Decrypt(pcose, 128, 16, pbKey, cbitKey / 8,
					cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_16_128_256
		case COSE_Algorithm_AES_CCM_16_128_256:
			if (!AES_CCM_Decrypt(pcose, 128, 16, pbKey, cbitKey / 8,
					cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_64_128
		case COSE_Algorithm_AES_CCM_64_64_128:
			if (!AES_CCM_Decrypt(pcose, 64, 64, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_64_256
		case COSE_Algorithm_AES_CCM_64_64_256:
			if (!AES_CCM_Decrypt(pcose, 64, 64, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_128_128
		case COSE_Algorithm_AES_CCM_64_128_128:
			if (!AES_CCM_Decrypt(pcose, 128, 64, pbKey, cbitKey / 8,
					cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_128_256
		case COSE_Algorithm_AES_CCM_64_128_256:
			if (!AES_CCM_Decrypt(pcose, 128, 64, pbKey, cbitKey / 8,
					cn->v.bytes, cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_GCM_128
		case COSE_Algorithm_AES_GCM_128:
			if (!AES_GCM_Decrypt(pcose, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_GCM_192
		case COSE_Algorithm_AES_GCM_192:
			if (!AES_GCM_Decrypt(pcose, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

#ifdef USE_AES_GCM_256
		case COSE_Algorithm_AES_GCM_256:
			if (!AES_GCM_Decrypt(pcose, pbKey, cbitKey / 8, cn->v.bytes,
					cn->length, pbAuthData, cbAuthData, perr)) {
				goto error;
			}
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
			break;
	}

	if (pbAuthData != nullptr) {
		COSE_FREE(pbAuthData, context);
	}
	if (pbKeyNew != nullptr) {
		COSE_FREE(pbKeyNew, context);
	}
	if (perr != nullptr) {
		perr->err = COSE_ERR_NONE;
	}

	return true;
}
#endif

#if INCLUDE_ENCRYPT
bool COSE_Enveloped_encrypt(HCOSE_ENVELOPED h, cose_errback *perr)
{
	COSE_Enveloped *pcose = (COSE_Enveloped *)h;

	CHECK_CONDITION(IsValidEnvelopedHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(
		pcose->m_recipientFirst != nullptr, COSE_ERR_INVALID_HANDLE);

	cose_errback coseError;
	if (perr == nullptr) {
		perr = &coseError;
	}

	return _COSE_Enveloped_encrypt(pcose, nullptr, 0, "Encrypt", perr);

errorReturn:
	return false;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0
bool _COSE_Enveloped_encrypt(COSE_Enveloped *pcose,
	const byte *pbKeyIn,
	size_t cbKeyIn,
	const char *szContext,
	cose_errback *perr)
{
	int alg;
	int t;
	COSE_RecipientInfo *pri;
	const cn_cbor *cn_Alg = nullptr;
	byte *pbAuthData = nullptr;
	size_t cbitKey;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
	bool fRet = false;
	byte *pbKeyNew = nullptr;
	const byte *pbKey = nullptr;
	size_t cbKey = 0;

	cn_Alg = _COSE_map_get_int(
		&pcose->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn_Alg == nullptr) {
	errorReturn:
		if (pbAuthData != nullptr) {
			COSE_FREE(pbAuthData, context);
		}
		if (pbKeyNew != nullptr) {
			memset(pbKeyNew, 0, cbKey);
			COSE_FREE(pbKeyNew, context);
		}
		return fRet;
	}

	CHECK_CONDITION((cn_Alg->type != CN_CBOR_TEXT), COSE_ERR_UNKNOWN_ALGORITHM);
	CHECK_CONDITION(
		(cn_Alg->type == CN_CBOR_UINT) || (cn_Alg->type == CN_CBOR_INT),
		COSE_ERR_INVALID_PARAMETER);
	alg = (int)cn_Alg->v.uint;

	//  Get the key size

	switch (alg) {
#ifdef USE_AES_CCM_64_64_128
		case COSE_Algorithm_AES_CCM_64_64_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_16_128_128
		case COSE_Algorithm_AES_CCM_16_128_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_64_128_128
		case COSE_Algorithm_AES_CCM_64_128_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_16_64_128
		case COSE_Algorithm_AES_CCM_16_64_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_CCM_64_64_256
		case COSE_Algorithm_AES_CCM_64_64_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_CCM_16_128_256
		case COSE_Algorithm_AES_CCM_16_128_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_CCM_64_128_256
		case COSE_Algorithm_AES_CCM_64_128_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_CCM_16_64_256
		case COSE_Algorithm_AES_CCM_16_64_256:
			cbitKey = 256;
			break;
#endif

#ifdef USE_AES_GCM_128
		case COSE_Algorithm_AES_GCM_128:
			cbitKey = 128;
			break;
#endif

#ifdef USE_AES_GCM_192
		case COSE_Algorithm_AES_GCM_192:
			cbitKey = 192;
			break;
#endif

#ifdef USE_AES_GCM_256
		case COSE_Algorithm_AES_GCM_256:
			cbitKey = 256;
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}

	//  Enveloped or Encrypted?

	if (pbKeyIn != nullptr) {
		CHECK_CONDITION(cbKeyIn == cbitKey / 8, COSE_ERR_INVALID_PARAMETER);
		pbKey = pbKeyIn;
		cbKey = cbKeyIn;
	}
#ifdef INCLUDE_ENCRYPT
	else {
		//  If we are doing direct encryption - then recipient generates the key

		t = 0;
		for (pri = pcose->m_recipientFirst; pri != nullptr;
			 pri = pri->m_recipientNext) {
			if (pri->m_encrypt.m_message.m_flags & 1) {
				CHECK_CONDITION(pbKey == nullptr, COSE_ERR_INVALID_PARAMETER);

				t |= 1;
				pbKeyNew =
					_COSE_RecipientInfo_generateKey(pri, alg, cbitKey, perr);
				cbKey = cbitKey / 8;
				if (pbKeyNew == nullptr) {
					goto errorReturn;
				}
			}
			else {
				t |= 2;
			}
		}
		CHECK_CONDITION(t != 3, COSE_ERR_INVALID_PARAMETER);

		if (t == 2) {
			pbKeyNew = (byte *)COSE_CALLOC(cbitKey / 8, 1, context);
			CHECK_CONDITION(pbKeyNew != nullptr, COSE_ERR_OUT_OF_MEMORY);
			cbKey = cbitKey / 8;
			rand_bytes(pbKeyNew, cbKey);
		}
		pbKey = pbKeyNew;
	}
#endif	// INCLUDE_ENCRYPT

	//  Build protected headers

	const cn_cbor *cbProtected =
		_COSE_encode_protected(&pcose->m_message, perr);
	if (cbProtected == nullptr) {
		goto errorReturn;
	}

	//  Build authenticated data

	size_t cbAuthData = 0;
	if (!_COSE_Encrypt_Build_AAD(
			&pcose->m_message, &pbAuthData, &cbAuthData, szContext, perr)) {
		goto errorReturn;
	}

	switch (alg) {
#ifdef USE_AES_CCM_16_64_128
		case COSE_Algorithm_AES_CCM_16_64_128:
			if (!AES_CCM_Encrypt(pcose, 64, 16, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_16_64_256
		case COSE_Algorithm_AES_CCM_16_64_256:
			if (!AES_CCM_Encrypt(pcose, 64, 16, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_16_128_128
		case COSE_Algorithm_AES_CCM_16_128_128:
			if (!AES_CCM_Encrypt(pcose, 128, 16, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_16_128_256
		case COSE_Algorithm_AES_CCM_16_128_256:
			if (!AES_CCM_Encrypt(pcose, 128, 16, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_64_128
		case COSE_Algorithm_AES_CCM_64_64_128:
			if (!AES_CCM_Encrypt(pcose, 64, 64, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_64_256
		case COSE_Algorithm_AES_CCM_64_64_256:
			if (!AES_CCM_Encrypt(pcose, 64, 64, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_128_128
		case COSE_Algorithm_AES_CCM_64_128_128:
			if (!AES_CCM_Encrypt(pcose, 128, 64, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_CCM_64_128_256
		case COSE_Algorithm_AES_CCM_64_128_256:
			if (!AES_CCM_Encrypt(pcose, 128, 64, pbKey, cbKey, pbAuthData,
					cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_GCM_128
		case COSE_Algorithm_AES_GCM_128:
			if (!AES_GCM_Encrypt(
					pcose, pbKey, cbKey, pbAuthData, cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_GCM_192
		case COSE_Algorithm_AES_GCM_192:
			if (!AES_GCM_Encrypt(
					pcose, pbKey, cbKey, pbAuthData, cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

#ifdef USE_AES_GCM_256
		case COSE_Algorithm_AES_GCM_256:
			if (!AES_GCM_Encrypt(
					pcose, pbKey, cbKey, pbAuthData, cbAuthData, perr)) {
				goto errorReturn;
			}
			break;
#endif

		default:
			FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}

#if INCLUDE_ENCRYPT
	for (pri = pcose->m_recipientFirst; pri != nullptr;
		 pri = pri->m_recipientNext) {
		if (!_COSE_Recipient_encrypt(pri, pbKey, cbKey, perr)) {
			goto errorReturn;
		}
	}
#endif	// INCLUDE_ENCRYPT

#if INCLUDE_COUNTERSIGNATURE
	if (pcose->m_message.m_counterSigners != nullptr) {
		if (!_COSE_CounterSign_Sign(
				&pcose->m_message, CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif

#if INCLUDE_COUNTERSIGNATURE1
	if (pcose->m_message.m_counterSign1 != NULL) {
		if (!_COSE_CounterSign1_Sign(
				&pcose->m_message, CBOR_CONTEXT_PARAM_COMMA perr)) {
			goto errorReturn;
		}
	}
#endif

	//  Figure out the clean up

	fRet = true;
	goto errorReturn;
}
#endif

#if INCLUDE_ENCRYPT
bool COSE_Enveloped_SetContent(HCOSE_ENVELOPED h,
	const byte *rgb,
	size_t cb,
	cose_errback *perr)
{
	CHECK_CONDITION(IsValidEnvelopedHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(rgb != nullptr, COSE_ERR_INVALID_PARAMETER);

	return _COSE_Enveloped_SetContent((COSE_Enveloped *)h, rgb, cb, perr);

errorReturn:
	return false;
}

/*!
 * @brief Set the application external data for authentication
 *
 * Enveloped data objects support the authentication of external application
 * supplied data.  This function is provided to supply that data to the library.
 *
 * The external data is not copied, nor will be it freed when the handle is
 * released.
 *
 * @param hcose  Handle for the COSE Enveloped data object
 * @param pbEternalData  point to the external data
 * @param cbExternalData size of the external data
 * @param perr  location to return errors
 * @return result of the operation.
 */

bool COSE_Enveloped_SetExternal(HCOSE_ENVELOPED hcose,
	const byte *pbExternalData,
	size_t cbExternalData,
	cose_errback *perr)
{
	CHECK_CONDITION(IsValidEnvelopedHandle(hcose), COSE_ERR_INVALID_HANDLE)
	CHECK_CONDITION((pbExternalData != nullptr) || (cbExternalData == 0),
		COSE_ERR_INVALID_PARAMETER);

	return _COSE_SetExternal(&((COSE_Enveloped *)hcose)->m_message,
		pbExternalData, cbExternalData, perr);

errorReturn:
	return false;
}

bool _COSE_Enveloped_SetContent(COSE_Enveloped *cose,
	const byte *rgb,
	size_t cb,
	cose_errback *perror)
{
	byte *pb;
	cose->pbContent = pb =
		(byte *)COSE_CALLOC(cb, 1, &cose->m_message.m_allocContext);
	if (cose->pbContent == nullptr) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_INVALID_PARAMETER;
		}
		return false;
	}
	memcpy(pb, rgb, cb);
	cose->cbContent = cb;

	return true;
}

/*! brief Retrieve header parameter from an enveloped message structure
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

cn_cbor *COSE_Enveloped_map_get_int(HCOSE_ENVELOPED h,
	int key,
	int flags,
	cose_errback *perror)
{
	if (!IsValidEnvelopedHandle(h)) {
		if (perror != nullptr) {
			perror->err = COSE_ERR_INVALID_HANDLE;
		}
		return nullptr;
	}

	return _COSE_map_get_int(
		&((COSE_Enveloped *)h)->m_message, key, flags, perror);
}

bool COSE_Enveloped_map_put_int(HCOSE_ENVELOPED h,
	int key,
	cn_cbor *value,
	int flags,
	cose_errback *perr)
{
	CHECK_CONDITION(IsValidEnvelopedHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != nullptr, COSE_ERR_INVALID_PARAMETER);

	return _COSE_map_put(
		&((COSE_Enveloped *)h)->m_message, key, value, flags, perr);

errorReturn:
	return false;
}

bool COSE_Enveloped_AddRecipient(HCOSE_ENVELOPED hEnc,
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

	CHECK_CONDITION(IsValidEnvelopedHandle(hEnc), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidRecipientHandle(hRecip), COSE_ERR_INVALID_HANDLE);

	pEncrypt = (COSE_Enveloped *)hEnc;
	pRecip = (COSE_RecipientInfo *)hRecip;

#ifdef USE_CBOR_CONTEXT
	context = &pEncrypt->m_message.m_allocContext;
#endif	// USE_CBOR_CONTEXT

	pRecip->m_recipientNext = pEncrypt->m_recipientFirst;
	pEncrypt->m_recipientFirst = pRecip;
	pRecip->m_encrypt.m_message.m_refCount++;

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

	return true;

errorReturn:
	return false;
}
#endif

#if INCLUDE_ENCRYPT || INCLUDE_ENCRYPT0 || INCLUDE_MAC || INCLUDE_MAC0
bool _COSE_Encrypt_Build_AAD(COSE *pMessage,
	byte **ppbAAD,
	size_t *pcbAAD,
	const char *szContext,
	cose_errback *perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context *context = &pMessage->m_allocContext;
#endif
	cn_cbor_errback cbor_error;
	byte *pbAuthData = nullptr;
	size_t cbAuthData;
	cn_cbor *pAuthData = nullptr;
	cn_cbor *pItem = nullptr;
	cn_cbor *ptmp = nullptr;

	//  Build authenticated data
	pAuthData = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(pAuthData != nullptr, cbor_error);

	ptmp =
		cn_cbor_string_create(szContext, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(ptmp != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = nullptr;

	pItem = _COSE_arrayget_int(pMessage, INDEX_PROTECTED);
	CHECK_CONDITION(pItem != nullptr, COSE_ERR_INVALID_PARAMETER);
	if ((pItem->length == 1) && (pItem->v.bytes[0] == 0xa0)) {
		ptmp = cn_cbor_data_create(
			nullptr, 0, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	else {
		ptmp = cn_cbor_data_create(pItem->v.bytes, (int)pItem->length,
			CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	}
	CHECK_CONDITION_CBOR(ptmp != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = nullptr;

	ptmp = cn_cbor_data_create(pMessage->m_pbExternal,
		(int)pMessage->m_cbExternal, CBOR_CONTEXT_PARAM_COMMA & cbor_error);
	CHECK_CONDITION_CBOR(ptmp != nullptr, cbor_error);
	CHECK_CONDITION_CBOR(
		cn_cbor_array_append(pAuthData, ptmp, &cbor_error), cbor_error);
	ptmp = nullptr;

	cbAuthData = cn_cbor_encode_size(pAuthData);
	pbAuthData = (byte *)COSE_CALLOC(cbAuthData, 1, context);
	CHECK_CONDITION(pbAuthData != nullptr, COSE_ERR_OUT_OF_MEMORY);
	CHECK_CONDITION((size_t)cn_cbor_encoder_write(
						pbAuthData, 0, cbAuthData, pAuthData) == cbAuthData,
		COSE_ERR_CBOR);

	*ppbAAD = pbAuthData;
	*pcbAAD = cbAuthData;

#if 0
        {
            printf("Encrypt* AAD = ");
            int iX;
            for (iX=0; iX < cbAuthData; iX++) {
                printf("%02x ", pbAuthData[iX]);
            }
            printf("\n");
        }
#endif

	if (pAuthData != nullptr) {
		CN_CBOR_FREE(pAuthData, context);
	}

	return true;

errorReturn:
	if (pbAuthData != nullptr) {
		COSE_FREE(pbAuthData, context);
	}
	if (ptmp != nullptr) {
		CN_CBOR_FREE(ptmp, nullptr);
	}
	if (pAuthData != nullptr) {
		CN_CBOR_FREE(pAuthData, context);
	}
	return false;
}
#endif

#if INCLUDE_ENCRYPT
HCOSE_RECIPIENT COSE_Enveloped_GetRecipient(HCOSE_ENVELOPED cose,
	int iRecipient,
	cose_errback *perr)
{
	int i;
	COSE_RecipientInfo *p = nullptr;

	CHECK_CONDITION(IsValidEnvelopedHandle(cose), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(iRecipient >= 0, COSE_ERR_INVALID_PARAMETER);

	p = ((COSE_Enveloped *)cose)->m_recipientFirst;
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

#endif
