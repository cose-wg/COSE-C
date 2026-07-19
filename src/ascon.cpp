#include "cose/cose.h"
#include "cose_int.h"

extern "C" {
    #include <string.h>
    // #include <ascon.h>

    int ascon_aead_encrypt_trunc(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
                           const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
                           const uint8_t* k, uint16_t t_bits);

    int ascon_aead_decrypt_trunc(uint8_t* m, const uint8_t* t, const uint8_t* c,
                           uint64_t clen, const uint8_t* ad, uint64_t adlen,
                           const uint8_t* npub, const uint8_t* k, uint16_t t_bits);
}

#define ASCON_KEY_SIZE 16
#define ASCON_NONCE_SIZE 16
// #define ASCON_TAG_SIZE 16

#define BYTES_TO_BITS(bytes) ((bytes) * 8u)
#define BITS_TO_BYTES(bits) (((bits) + 7u) / 8u)

bool Ascon_AEAD128_Encrypt(COSE_Enveloped *pcose,
                           const byte *pbKey,
                           size_t cbKey,
                           const byte *pbAuthData,
                           size_t cbAuthData,
                           size_t cbitTag,
                           cose_errback *perr)
{
    size_t cbOut;
    byte *rgbOut = nullptr;
    static byte rgbIV[ASCON_NONCE_SIZE] = {0};
    const cn_cbor *pIV = nullptr;
//    const EVP_CIPHER *cipher;
#ifdef USE_CBOR_CONTEXT
    cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif
    //  Setup the IV/Nonce and put it into the message

    pIV = _COSE_map_get_int(
            &pcose->m_message, COSE_Header_IV, COSE_BOTH, nullptr);
    if ((pIV == nullptr) || (pIV->type != CN_CBOR_BYTES)) {
        if (perr != nullptr) {
            perr->err = COSE_ERR_INVALID_PARAMETER;
        }

        errorReturn:
        if (rgbOut != nullptr) {
            COSE_FREE(rgbOut, context);
        }
        return false;
    }

    CHECK_CONDITION(cbKey == ASCON_KEY_SIZE, COSE_ERR_INVALID_PARAMETER)
    CHECK_CONDITION(pIV->length == ASCON_NONCE_SIZE, COSE_ERR_INVALID_PARAMETER);
    memcpy(rgbIV, pIV->v.str, pIV->length);

    cbOut = pcose->cbContent + BITS_TO_BYTES(cbitTag);
    rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
    CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

    const int enc_result = ascon_aead_encrypt_trunc(rgbOut + pcose->cbContent,
        rgbOut, pcose->pbContent, pcose->cbContent,
        pbAuthData, cbAuthData, rgbIV, pbKey, cbitTag);
    CHECK_CONDITION(enc_result == 0, COSE_ERR_CRYPTO_FAIL)

    cn_cbor *cnTmp = cn_cbor_data_create2(rgbOut,
                                          cbOut, 0, CBOR_CONTEXT_PARAM_COMMA nullptr);
    CHECK_CONDITION(cnTmp != nullptr, COSE_ERR_CBOR);
    rgbOut = nullptr;
    CHECK_CONDITION(_COSE_array_replace(&pcose->m_message, cnTmp, INDEX_BODY,
                                        CBOR_CONTEXT_PARAM_COMMA nullptr),
                    COSE_ERR_CBOR);

    return true;
}

bool Ascon_AEAD128_Decrypt(COSE_Enveloped *pcose,
                     const byte *pbKey,
                     size_t cbKey,
                     const byte *pbCrypto,
                     size_t cbCrypto,
                     const byte *pbAuthData,
                     size_t cbAuthData,
                     size_t cbitTag,
                     cose_errback *perr)
{
    size_t cbOut;
    byte *rgbOut = nullptr;
    static byte rgbIV[ASCON_NONCE_SIZE] = {0};
    const cn_cbor *pIV = nullptr;
#ifdef USE_CBOR_CONTEXT
    cn_cbor_context *context = &pcose->m_message.m_allocContext;
#endif

    //  Setup the IV/Nonce and put it into the message
    pIV = _COSE_map_get_int(
            &pcose->m_message, COSE_Header_IV, COSE_BOTH, nullptr);
    if ((pIV == nullptr) || (pIV->type != CN_CBOR_BYTES)) {
        if (perr != nullptr) {
            perr->err = COSE_ERR_INVALID_PARAMETER;
        }

        errorReturn:
        if (rgbOut != nullptr) {
            COSE_FREE(rgbOut, context);
        }
        return false;
    }

    CHECK_CONDITION(cbKey == ASCON_KEY_SIZE, COSE_ERR_INVALID_PARAMETER)
    CHECK_CONDITION(pIV->length == ASCON_NONCE_SIZE, COSE_ERR_INVALID_PARAMETER);
    memcpy(rgbIV, pIV->v.str, pIV->length);

    cbOut = cbCrypto - BITS_TO_BYTES(cbitTag);
    rgbOut = (byte *)COSE_CALLOC(cbOut, 1, context);
    CHECK_CONDITION(rgbOut != nullptr, COSE_ERR_OUT_OF_MEMORY);

    const int enc_result = ascon_aead_decrypt_trunc(rgbOut, pbCrypto + cbOut,
        pbCrypto, cbOut, pbAuthData, cbAuthData, rgbIV, pbKey, cbitTag);
    CHECK_CONDITION(enc_result == 0, COSE_ERR_CRYPTO_FAIL)

    pcose->pbContent = rgbOut;
    pcose->cbContent = cbOut;
    return true;
}
