#pragma once

#include <memory>

namespace cose {

template <typename T>
inline std::shared_ptr<T> make_managed_array(size_t size)
{
	return std::shared_ptr<T>(new T[size], [](T *p) { delete[] p; });
}

}  // namespace cose