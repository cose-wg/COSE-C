#
#  Compiling/running tests
#

if (use_context)
   add_definitions(-DUSE_CBOR_CONTEXT)
endif()

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/dumper )

add_executable ( cose_dumper dumper.c )

target_link_libraries (cose_dumper PRIVATE cose-c )

## OpenSSL
message ( "LIBS: *** ${OPENSSL_LIBRARIES}")
message ( "INC: *** ${OPENSSL_INCLUDE_DIR}")

target_include_directories(cose_dumper PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries( cose_dumper PRIVATE event_openssl)
target_link_libraries( cose_dumper PRIVATE ${OPENSSL_LIBRARIES} )
target_link_libraries( cose_dumper PRIVATE cn-cbor )

target_include_directories ( cose_dumper PRIVATE ../include )
target_include_directories ( cose_dumper PRIVATE ../src )
target_include_directories ( cose_dumper PUBLIC ../../cose/cn-cbor/include )
target_include_directories ( cose_dumper PUBLIC ../../cn-cbor/implement/cn-cbor/include )

enable_testing()
# add_test ( NAME cose_dumper COMMAND cose_dumper )

