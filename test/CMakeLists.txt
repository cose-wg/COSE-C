#
#  Compiling/running tests
#

if (use_context)
   add_definitions(-DUSE_CBOR_CONTEXT)
endif()

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/test )

add_executable ( cose_test test.c )
target_link_libraries (cose_test PRIVATE cose-c )
target_include_directories ( cose_test PRIVATE ../include )
target_include_directories ( cose_test PRIVATE ../src )
target_include_directories ( cose_test PUBLIC ../../cose/cn-cbor/include )

add_test ( NAME cose_test COMMAND test )
