find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h PATHS "/usr/local" "/usr" "C:/Program Files (x86)/mbed TLS/include")

find_library(MBEDTLS_LIBRARY mbedtls PATHS "C:/Program Files (x86)/mbed TLS/lib")
find_library(MBEDX509_LIBRARY mbedx509 PATHS "C:/Program Files (x86)/mbed TLS/lib")
find_library(MBEDCRYPTO_LIBRARY mbedcrypto PATHS "C:/Program Files (x86)/mbed TLS/lib")

set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY
                                  MBEDCRYPTO_LIBRARY)

mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

message(STATUS "MBEDTLS_INCLUDE_DIRS: ${MBEDTLS_INCLUDE_DIRS}")
message(STATUS "MBEDTLS_LIBRARY: ${MBEDTLS_LIBRARY}")
message(STATUS "MBEDX509_LIBRARY: ${MBEDX509_LIBRARY}")
message(STATUS "MBEDCRYPTO_LIBRARY: ${MBEDCRYPTO_LIBRARY}")
message(STATUS "MBEDTLS_LIBRARIES: ${MBEDTLS_LIBRARIES}")

if(NOT TARGET mbedtls)
  add_library(mbedtls IMPORTED UNKNOWN)
  set_target_properties(mbedtls PROPERTIES IMPORTED_LOCATION ${MBEDTLS_LIBRARIES})
  set_target_properties(mbedtls PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}")
endif()
