#include <cassert>

#include "cn-cbor/cn-cbor.h"
#include <cose/cose.h>
#include <stdlib.h>

#ifdef __MBED__
#include <string.h>
#else
#include <memory.h>
#endif

#define INIT_CB(v)                                     \
	if (errp) {                                        \
		errp->err = CN_CBOR_NO_ERROR;                  \
	}                                                  \
	(v) = static_cast<cn_cbor *>(CN_CALLOC_CONTEXT()); \
	if (!(v)) {                                        \
		if (errp) {                                    \
			errp->err = CN_CBOR_ERR_OUT_OF_MEMORY;     \
		}                                              \
		return false;                                  \
	}

#ifdef USE_CBOR_CONTEXT
#define CBOR_CONTEXT_PARAM , context
#define CBOR_CONTEXT_PARAM_COMMA context,

#if 1
#define CN_CALLOC(ctx)                                           \
	((ctx) && (ctx)->calloc_func)                                \
		? (ctx)->calloc_func(1, sizeof(cn_cbor), (ctx)->context) \
		: calloc(1, sizeof(cn_cbor))
#endif

#define CN_CALLOC_CONTEXT() CN_CALLOC(context)
#define CN_CBOR_CALLOC(c, i, ctx)                                            \
	((ctx) && (ctx)->calloc_func) ? (ctx)->calloc_func(c, i, (ctx)->context) \
								  : calloc(c, i)
#define COSE_FREE(ptr, ctx)                                                    \
	((((ctx) && (ctx)->free_func)) ? ((ctx)->free_func((ptr), (ctx)->context)) \
								   : free((ptr)))

#else
#define CBOR_CONTEXT_PARAM
#define CBOR_CONTEXT_PARAM_COMMA
#define CN_CALLOC(ctx) calloc(1, sizeof(cn_cbor))
#define CN_CALLOC_CONTEXT() CN_CALLOC(context)
#define CN_CBOR_CALLOC(c, i, ctx) calloc(c, i)
#define COSE_FREE(ptr, ctx) free(ptr)
#endif

/***
 * Replace the i-th element in the array.
 * Extend the array if necessary so it has enough elements.
 *
 * @param[in]   cb_array		Array to use
 * @param[in]	cb_value    	New item to be placed in the array
 * @param[in]	index			Zero based index to be used
 * @param[in]	CBOR_CONTEXT	Context based allocation structure
 * @param[in,out] errp			CBOR error return on failure
 * returns						Did we succeed?
 */

bool cn_cbor_array_replace(cn_cbor *cb_array,
	cn_cbor *cb_value,
	int index,
	CBOR_CONTEXT_COMMA cn_cbor_errback *errp)
{
	int i;
	cn_cbor *cb_temp;
	cn_cbor *cb_temp2;

	if (!cb_array || !cb_value || cb_array->type != CN_CBOR_ARRAY) {
		if (errp != nullptr) {
			errp->err = CN_CBOR_ERR_INVALID_PARAMETER;
		}
		return false;
	}

	if (index == 0) {
		if (cb_array->length > 0) {
			cb_temp = cb_array->first_child;

			cb_value->parent = cb_array;
			cb_value->next = cb_temp->next;
			if (cb_array->last_child == cb_temp) {
				cb_array->last_child = cb_value;
			}
			cb_array->first_child = cb_value;
			cb_temp->parent = nullptr;
			cb_temp->next = nullptr;
			cn_cbor_free(cb_temp CBOR_CONTEXT_PARAM);
			return true;
		}
		return cn_cbor_array_append(cb_array, cb_value, errp);
	}

	if (cb_array->first_child == nullptr) {
		INIT_CB(cb_temp2);
		cb_array->first_child = cb_array->last_child = cb_temp2;
		cb_temp2->parent = cb_array;
		cb_array->length = 1;
		cb_temp2->type = CN_CBOR_INVALID;
	}

	cb_temp = cb_array->first_child;
	for (i = 1; i < index; i++) {
		if (cb_temp->next == nullptr) {
			INIT_CB(cb_temp2);
			cb_temp2->type = CN_CBOR_INVALID;
			cb_temp->next = cb_temp2;
			cb_temp2->parent = cb_array;
			cb_array->last_child = cb_temp2;
			cb_array->length += 1;
		}

		cb_temp = cb_temp->next;
	}

	if (cb_temp->next == nullptr) {
		cb_temp->next = cb_value;
		cb_value->parent = cb_array;
		cb_array->last_child = cb_value;
		cb_array->length += 1;
		return true;
	}

	cb_temp2 = cb_temp->next;
	cb_value->next = cb_temp2->next;
	cb_temp->next = cb_value;
	cb_value->parent = cb_array;
	if (cb_array->last_child == cb_temp2) {
		cb_array->last_child = cb_value;
	}

	cb_temp2->next = nullptr;
	cb_temp2->parent = nullptr;
	cn_cbor_free(cb_temp2 CBOR_CONTEXT_PARAM);

	return true;
}

cn_cbor *cn_cbor_clone(const cn_cbor *pIn,
	CBOR_CONTEXT_COMMA cn_cbor_errback *pcn_cbor_error)
{
	cn_cbor *pOut = nullptr;
	char *sz;
	unsigned char *pb;
	cn_cbor *pTemp;
	cn_cbor *pLast;
	int count;

	switch (pIn->type) {
		case CN_CBOR_TEXT:
			sz = (char *)(CN_CBOR_CALLOC(pIn->length + 1, 1, context));
			if (sz == nullptr) {
				return nullptr;
			}
			memcpy(sz, pIn->v.str, pIn->length);
			sz[pIn->length] = 0;
			pOut = cn_cbor_string_create2(
				sz, 0 CBOR_CONTEXT_PARAM, pcn_cbor_error);
			if (pOut == nullptr) {
				COSE_FREE(sz, context);
			}
			break;

		case CN_CBOR_UINT:
			pOut = cn_cbor_int_create(
				pIn->v.sint CBOR_CONTEXT_PARAM, pcn_cbor_error);
			break;

		case CN_CBOR_INT:
			pOut = cn_cbor_int_create(
				pIn->v.uint CBOR_CONTEXT_PARAM, pcn_cbor_error);
			break;

		case CN_CBOR_TRUE:
			pOut = cn_cbor_bool_create(true CBOR_CONTEXT_PARAM, pcn_cbor_error);
			break;

		case CN_CBOR_FALSE:
			pOut =
				cn_cbor_bool_create(false CBOR_CONTEXT_PARAM, pcn_cbor_error);
			break;

		case CN_CBOR_BYTES:
			pb = static_cast<unsigned char *>(
				CN_CBOR_CALLOC((int)pIn->length, 1, context));
			if (pb == nullptr) {
				return nullptr;
			}
			memcpy(pb, pIn->v.bytes, pIn->length);
			pOut = cn_cbor_data_create2(
				pb, (int)pIn->length, 0 CBOR_CONTEXT_PARAM, pcn_cbor_error);
			if (pOut == nullptr) {
				COSE_FREE((cn_cbor *)pb, context);
			}
			break;

		case CN_CBOR_MAP:
			pOut = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA pcn_cbor_error);
			if (pOut == nullptr) {
				return nullptr;
			}
			pTemp = pIn->first_child;
			pLast = nullptr;
			count = 0;
			while (pTemp != nullptr) {
				cn_cbor *p = cn_cbor_clone(
					pTemp, CBOR_CONTEXT_PARAM_COMMA pcn_cbor_error);
				if (p == nullptr) {
					cn_cbor_free(pOut CBOR_CONTEXT_PARAM);
					return nullptr;
				}
				if (pLast == nullptr) {
					pOut->first_child = p;
					pLast = p;
				}
				else {
					pLast->next = p;
					pLast = p;
				}
				p->parent = pOut;
				count += 1;
				pTemp = pTemp->next;
			}
			pOut->last_child = pLast;
			pOut->length = count;
			break;

		default:
			assert(false);
			break;
	}

	return pOut;
}

#ifndef CN_CBOR_VERSION
cn_cbor *cn_cbor_tag_create(int tag,
	cn_cbor *child,
	CBOR_CONTEXT_COMMA cn_cbor_errback *perr)
{
	cn_cbor *pcnTag = CN_CALLOC(context);
	if (pcnTag == nullptr) {
		if (perr != nullptr) {
			perr->err = CN_CBOR_ERR_OUT_OF_MEMORY;
		}
		return nullptr;
	}

	pcnTag->type = CN_CBOR_TAG;
	pcnTag->v.sint = tag;
	pcnTag->first_child = child;
	child->parent = pcnTag;

	return pcnTag;
}

cn_cbor *cn_cbor_bool_create(int boolValue,
	CBOR_CONTEXT_COMMA cn_cbor_errback *errp)
{
	cn_cbor *pcn = CN_CALLOC(context);
	if (pcn == nullptr) {
		if (errp != nullptr) {
			errp->err = CN_CBOR_ERR_OUT_OF_MEMORY;
		}
		return nullptr;
	}

	pcn->type = CN_CBOR_FALSE + (boolValue != 0);
	return pcn;
}

cn_cbor *cn_cbor_null_create(CBOR_CONTEXT_COMMA cn_cbor_errback *errp)
{
	cn_cbor *pcn = CN_CALLOC(context);
	if (pcn == nullptr) {
		if (errp != nullptr) {
			errp->err = CN_CBOR_ERR_OUT_OF_MEMORY;
		}
		return nullptr;
	}
	pcn->type = CN_CBOR_NULL;
	return pcn;
}
#endif

size_t cn_cbor_encode_size(cn_cbor *object)
{
	ssize_t size = cn_cbor_encoder_write(nullptr, 0, 0, object);
	return size >= 0 ? size : 0;
}
