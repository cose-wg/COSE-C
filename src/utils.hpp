#pragma once

#include <memory>

#include "cose/cose.h"

namespace cose {

template <typename T>
inline std::shared_ptr<T> make_managed_array(size_t size)
{
	return std::shared_ptr<T>(new T[size], [](T* p) { delete[] p; });
}

#ifdef USE_CBOR_CONTEXT
template <typename T>
inline std::shared_ptr<T> make_managed_array(size_t size,
	cn_cbor_context* context)
{
	return std::shared_ptr<T>(
		COSE_CALLOC(1, size, context), [=](T* p) { COSE_FREE(p, context); });
}
#endif

}  // namespace cose