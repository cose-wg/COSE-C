#
# Compiling/running tests
#

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/dumper)

add_executable(cose_dumper dumper.c)

target_link_libraries(cose_dumper PRIVATE cose-c)

# target_link_libraries( cose_dumper PRIVATE event_openssl)
target_link_libraries(cose_dumper PULIC cn-cbor::cn-cbor)

if(MSVC)
  message("test: ${build_shared_libs}")
  message("verbose: ${verbose}")

  target_link_libraries(cose_dumper PRIVATE ws2_32)
endif()

if(use_embedtls)
  target_include_directories(
    cose_dumper
    PUBLIC
      ${CMAKE_SHARED_MODLE_PREFIX}embedtls${CMAKE_SHARED_LIBRARY_SUFFIX}/include
  )
  target_link_libraries(cose_dumper PRIVATE embedtls)
else()
  target_include_directories(cose_dumper PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(cose_dumper PRIVATE ${OPENSSL_LIBRARIES})
endif()

enable_testing()
# add_test ( NAME cose_dumper COMMAND cose_dumper )
