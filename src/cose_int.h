// These definitions are here because they aren't required for the public
// interface, and they were quite confusing in cn-cbor.h

typedef struct {
	int m_flags;        //  Not sure what goes here yet
	int m_ownMsg : 1;	//  Do I own the pointer @ m_cbor?
	int m_ownUnprotectedMap : 1; //  Do I own the pointer @ m_unportectedMap?
	int m_msgType : 4;	//  What message type is this?
	cn_cbor * m_cbor;
	cn_cbor * m_protectedMap;
	cn_cbor * m_unprotectMap;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context m_allocContext;
#endif
} COSE;

typedef struct {
	COSE m_message;	    // The message object
} COSE_SignMessage;


struct _RecipientInfo;
typedef struct _RecipientInfo COSE_RecipientInfo;

typedef struct {
	COSE m_message;		// The message object
	COSE_RecipientInfo * m_recipientFirst;
	byte * pbContent;
	size_t cbContent;
	byte * pbKey;
	size_t cbKey;
//	byte * pbIV;
//	size_t cbIV;
} COSE_Encrypt;

typedef struct _RecipientInfo {
	COSE_Encrypt m_encrypt;
	COSE_RecipientInfo * m_recipientNext;
} COSE_RecipientInfo;


#ifdef USE_CBOR_CONTEXT
/**
* Allocate enough space for 1 `cn_cbor` structure.
*
* @param[in]  ctx  The allocation context, or NULL for calloc.
* @return          A pointer to a `cn_cbor` or NULL on failure
*/
#define CN_CALLOC(ctx) ((ctx) && (ctx)->calloc_func) ? \
    (ctx)->calloc_func(1, sizeof(cn_cbor), (ctx)->context) : \
    calloc(1, sizeof(cn_cbor));

/**
*  Allocate space required
*
* @param[in]	ctx  The allocation context, or NULL for normal calloc.
* @param[in]	count	Number of items to allocate
* @param[in]	size	Size of item to allocate
* @return				A pointer to the object needed
*/
#define COSE_CALLOC(count, size, ctx) ((((ctx)) && ((ctx)->calloc_func)) ? \
	((ctx)->calloc_func(count, size, (ctx)->context)) : \
	calloc(count, size))

/**
* Free a
* @param  free_func [description]
* @return           [description]
*/
#define COSE_FREE(ptr, ctx) (((ctx) && (ctx)->free_func) ? \
    ((ctx)->free_func((ptr), (ctx)->context)) : \
    free((ptr)))

#define CBOR_CONTEXT_PARAM , context
#define CBOR_CONTEXT_PARAM_COMMA context ,
//#define CN_CALLOC_CONTEXT() CN_CALLOC(context)
#define CN_CBOR_FREE(p, context) cn_cbor_free(p, context)

#else

#define CBOR_CONTEXT_PARAM
#define CN_CALLOC_CONTEXT() CN_CALLOC
#define COSE_CALLOC(ctx, count, size) calloc(count, size)
#define CN_CBOR_FREE(p, context) cn_cbor_free(p)

#define COSE_FREE(ptr, ctx) free(ptr)

#endif // USE_CBOR_CONTEXT

#ifndef UNUSED_PARAM
#define UNUSED_PARAM(p) ((void)&(p))
#endif

extern bool IsValidEncryptHandle(HCOSE_ENCRYPT h);
extern bool IsValidRecipientHandle(HCOSE_RECIPIENT h);

extern bool _COSE_Init(COSE * pcose, CBOR_CONTEXT_COMMA cose_errback * errp);
extern bool _COSE_Init_From_Object(COSE* pobj, cn_cbor * pcbor, CBOR_CONTEXT_COMMA cose_errback * perror);
extern void _COSE_Release(COSE * pcose);

extern const cn_cbor * _COSE_map_get_string(COSE * cose, const char * key, int flags, cose_errback * errp);
extern const cn_cbor * _COSE_map_get_int(COSE * cose, int key, int flags, cose_errback * errp);
extern bool _COSE_map_put(COSE * cose, int key, cn_cbor * value, int flags, cose_errback * errp);

extern HCOSE_ENCRYPT _COSE_Encrypt_Init_From_Object(cn_cbor *, COSE_Encrypt * pIn, CBOR_CONTEXT_COMMA cose_errback * errp);
extern void _COSE_Encrypt_Release(COSE_Encrypt * p);
extern bool _COSE_Encrypt_decrypt(COSE_Encrypt * pbody, COSE_RecipientInfo * pRecip, cose_errback * perr);
extern void _COSE_Encrypt_SetContent(COSE_Encrypt * cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);

extern COSE_RecipientInfo * _COSE_Recipient_Init_From_Object(cn_cbor *, CBOR_CONTEXT_COMMA cose_errback * errp);
extern void _COSE_Recipient_Free(COSE_RecipientInfo *);
extern bool _COSE_Recipient_decrypt(COSE_RecipientInfo * pRecip, int cbitKey, byte * pbKey, cose_errback * errp);
extern byte * _COSE_RecipientInfo_generateKey(COSE_RecipientInfo * pRecipient, size_t cbitKeySize);
