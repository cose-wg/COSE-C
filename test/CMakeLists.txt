add_executable(cose_test test.c json.c encrypt.c sign.c context.c mac_test.c)

target_link_libraries(cose_test PRIVATE cose-c)
if(COSE_C_USE_MBEDTLS)
  target_link_libraries(cose_test PRIVATE mbedtls)
  target_include_directories(cose_test PRIVATE ${MBEDTLS_INCLUDE_DIRS})
  target_link_libraries(cose_test PRIVATE ${MBEDTLS_LIBRARY})
else()
  target_include_directories(cose_test PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(cose_test PRIVATE ${OPENSSL_LIBRARIES})
endif()

target_link_libraries(cose_test PRIVATE cn-cbor)
if(MSVC)
  target_link_libraries(cose_test PRIVATE ws2_32)
endif()

target_include_directories(cose_test PRIVATE ../src)

enable_testing()

add_test(NAME cose_test COMMAND ${CMAKE_BINARY_DIR}/bin/cose_test)

add_test(
  NAME RFC8152
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/RFC8152")

add_test(
  NAME aes-ccm
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/aes-ccm-examples")

add_test(
  NAME aes-gcm
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/aes-gcm-examples")

add_test(
  NAME enveloped
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/enveloped-tests")
add_test(
  NAME encrypted
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/encrypted-tests")

add_test(
  NAME cbc-mac
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/cbc-mac-examples")

add_test(
  NAME ecdsa
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/ecdsa-examples")

add_test(
  NAME hmac
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/hmac-examples")
add_test(
  NAME mac
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/mac-tests")
add_test(
  NAME mac0
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/mac0-tests")

add_test(
  NAME hkdf-hmac-sha
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/hkdf-hmac-sha-examples")
add_test(
  NAME hkdf-aes
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/hkdf-aes-examples")

add_test(
  NAME aes-wrap
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/aes-wrap-examples")

add_test(
  NAME ecdh-direct
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/ecdh-direct-examples")
add_test(
  NAME ecdh-wrap
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/ecdh-wrap-examples")
add_test(
  NAME sign
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/sign-tests")
add_test(
  NAME sign1
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --dir "${PROJECT_SOURCE_DIR}/Examples/sign1-tests")

add_test(
  NAME corner-cases
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --corners)

add_test(
  NAME Memory-mac-hmac
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/hmac-examples/HMac-01.json")
add_test(
  NAME Memory-mac-cbc-mac
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/cbc-mac-examples/cbc-mac-01.json")
add_test(
  NAME Memory-mac0
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/hmac-examples/HMac-enc-01.json")

add_test(
  NAME Memory-encrypt-gcm
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/aes-gcm-examples/aes-gcm-enc-01.json")
add_test(
  NAME Memory-encrypt-ccm
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/aes-ccm-examples/aes-ccm-enc-01.json")
add_test(
  NAME Memory-enveloped
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/aes-gcm-examples/aes-gcm-01.json")

# add_test(
  # NAME Memory-ecdh
  # WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  # COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/ecdh-direct-examples/p256-hkdf-256-01.json")
add_test(
  NAME Memory-aes-kw
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/aes-wrap-examples/aes-wrap-128-01.json")

add_test(
  NAME Memory-sign0
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/ecdsa-examples/ecdsa-sig-01.json")
add_test(
  NAME Memory-sign
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND cose_test --memory "${PROJECT_SOURCE_DIR}/Examples/ecdsa-examples/ecdsa-01.json")
