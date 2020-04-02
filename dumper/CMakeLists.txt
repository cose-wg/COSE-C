set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/dumper)

add_executable(cose_dumper dumper.c)
target_link_libraries(cose_dumper PRIVATE cose-c)

if(MSVC)
  message("test: ${BUILD_SHARED_LIBS}")
  target_link_libraries(cose_dumper PRIVATE ws2_32)
endif()

if(COSE_C_USE_EMBEDTLS)
  target_link_libraries(cose_dumper PRIVATE mbedtls)
else()
  target_include_directories(cose_dumper PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(cose_dumper PRIVATE ${OPENSSL_LIBRARIES})
endif()

enable_testing()
# add_test ( NAME cose_dumper COMMAND cose_dumper )
