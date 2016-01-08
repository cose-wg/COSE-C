#
#  Compiling/running tests
#

if (use_context)
   add_definitions(-DUSE_CBOR_CONTEXT)
endif()

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/test )

add_executable ( cose_test test.c json.c encrypt.c sign.c context.c )

target_link_libraries (cose_test PRIVATE cose-c )

## OpenSSL

target_include_directories(cose_test PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries( cose_test PRIVATE ${OPENSSL_LIBRARIES} )
target_link_libraries( cose_test PRIVATE cn-cbor )
if ( MSVC )
    target_link_libraries( cose_test PRIVATE ws2_32 )
endif ()

target_include_directories ( cose_test PRIVATE ../include )
target_include_directories ( cose_test PRIVATE ../src )
target_include_directories ( cose_test PUBLIC ../../cose/cn-cbor/include )
target_include_directories ( cose_test PUBLIC ../../cn-cbor/implement/cn-cbor/include )

enable_testing()

add_test ( NAME cose_test COMMAND cose_test )
add_test ( NAME mac-02 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/spec-examples/Mac-02.json )
add_test ( NAME mac-04 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/spec-examples/Mac-04.json )
add_test ( NAME sig-01 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/spec-examples/Sig-01.json )
add_test ( NAME sig-03 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/spec-examples/Sig-03.json )
add_test ( NAME sig-04 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/spec-examples/Sig-04.json )

add_test ( NAME hmac-01 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/hmac-examples/HMac-01.json )
add_test ( NAME hmac-02 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/hmac-examples/HMac-02.json )
add_test ( NAME hmac-03 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/hmac-examples/HMac-03.json )
add_test ( NAME hmac-04 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/hmac-examples/HMac-04.json )
add_test ( NAME hmac-05 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/hmac-examples/HMac-05.json )

add_test ( NAME cbc-mac-01 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/cbc-mac-examples/cbc-mac-01.json )
add_test ( NAME cbc-mac-02 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/cbc-mac-examples/cbc-mac-02.json )
add_test ( NAME cbc-mac-03 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/cbc-mac-examples/cbc-mac-03.json )
add_test ( NAME cbc-mac-04 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/cbc-mac-examples/cbc-mac-04.json )

add_test ( NAME aes-gcm-01 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-gcm-examples/aes-gcm-01.json )
add_test ( NAME aes-gcm-02 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-gcm-examples/aes-gcm-02.json )
add_test ( NAME aes-gcm-03 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-gcm-examples/aes-gcm-03.json )
add_test ( NAME aes-gcm-04 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-gcm-examples/aes-gcm-04.json )

add_test ( NAME aes-ccm-01 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-01.json )
add_test ( NAME aes-ccm-02 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-02.json )
add_test ( NAME aes-ccm-03 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-03.json )
add_test ( NAME aes-ccm-04 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-04.json )
add_test ( NAME aes-ccm-05 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-05.json )
add_test ( NAME aes-ccm-06 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-06.json )
add_test ( NAME aes-ccm-07 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-07.json )
add_test ( NAME aes-ccm-08 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cose_test Examples/aes-ccm-examples/aes-ccm-08.json )


