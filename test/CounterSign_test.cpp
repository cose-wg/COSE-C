//  encrypt.c

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cose/cose.h>
#include <cose/cose_configure.h>
#include <cn-cbor/cn-cbor.h>

#if INCLUDE_COUNTERSIGNATURE

#include "test.h"
#include "cose_int.h"

void CounterSign_Corners()
{
	HCOSE_COUNTERSIGN hCounterSign = nullptr;
	HCOSE_COUNTERSIGN hBadHandle = nullptr;
	HCOSE_COUNTERSIGN hNULL = nullptr;
	cose_errback cose_error;
	byte rgb[10];

	cn_cbor *cn = cn_cbor_int_create(5, CBOR_CONTEXT_PARAM_COMMA nullptr);

	hCounterSign = COSE_CounterSign_Init(CBOR_CONTEXT_PARAM_COMMA nullptr);
	hBadHandle = (HCOSE_COUNTERSIGN)COSE_CALLOC(1, sizeof(COSE), context);
#if INCLUDE_SIGN1
	HCOSE_SIGN1 hSign1 = COSE_Sign1_Init(
		COSE_INIT_FLAGS_NONE, CBOR_CONTEXT_PARAM_COMMA & cose_error);
#endif
	//  Look for invalid parameter
	//		Null handle checks
	//		bad handle checks
	//		null pointers

	CHECK_FAILURE(
		COSE_CounterSign_map_get_int(hNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_CounterSign_map_get_int(hNULL, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_CounterSign_map_get_int(hCounterSign, 1, COSE_BOTH, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

	CHECK_FAILURE(COSE_CounterSign_map_put_int(
					  hNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_CounterSign_map_put_int(
					  hNULL, 1, cn, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_CounterSign_map_put_int(
					  hNULL, 1, nullptr, COSE_PROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(COSE_CounterSign_map_put_int(hCounterSign, 1, cn,
					  COSE_PROTECT_ONLY | COSE_UNPROTECT_ONLY, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);

#if INCLUDE_SIGN1
	CHECK_FAILURE(
		COSE_Sign1_add_countersignature(hSign1, hBadHandle, &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	((COSE_CounterSign *)hCounterSign)->m_next = (COSE_CounterSign *)hBadHandle;
	CHECK_FAILURE(
		COSE_Sign1_add_countersignature(hSign1, hCounterSign, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	CHECK_FAILURE(COSE_Sign1_get_countersignature(hSign1, 3, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
	((COSE_CounterSign *)hCounterSign)->m_next = nullptr;
	COSE_Sign1_add_countersignature(hSign1, hCounterSign, &cose_error);
	CHECK_FAILURE(COSE_Sign1_get_countersignature(hSign1, 3, &cose_error),
		COSE_ERR_INVALID_PARAMETER, CFails++);
#endif

	CHECK_FAILURE(
		COSE_CounterSign_SetExternal(hNULL, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	CHECK_FAILURE(
		COSE_CounterSign_SetExternal(hBadHandle, rgb, sizeof(rgb), &cose_error),
		COSE_ERR_INVALID_HANDLE, CFails++);
	COSE_CounterSign_SetExternal(hCounterSign, rgb, sizeof(rgb), &cose_error);

	CHECK_RETURN(!COSE_CounterSign_Free(hBadHandle), false, CFails++);

	COSE_CounterSign_Free(hCounterSign);
#if INCLUDE_SIGN1
	COSE_Sign1_Free(hSign1);
#endif
}
#endif
