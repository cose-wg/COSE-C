#pragma once

#ifdef USE_CBOR_CONTEXT

cn_cbor_context* CreateContext(int failNumber);
void FreeContext(cn_cbor_context* pContext);
int IsContextEmpty(cn_cbor_context* pContext);

#endif	// USE_CBOR_CONTEXT
