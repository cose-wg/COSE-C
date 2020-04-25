set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/dumper)

add_executable(cose_dumper dumper.c)
target_link_libraries(cose_dumper PRIVATE cn-cbor::cn-cbor cose-c::cose-c)
if(MSVC)
  target_link_libraries(cose_dumper PRIVATE ws2_32)
endif()

target_include_directories(cose_dumper PRIVATE ../src)

if(COSE_C_USE_MBEDTLS)
  # mbedtls
  target_include_directories(cose_dumper
                             PUBLIC ${CMAKE_SHARED_MODLE_PREFIX}mbedtls${CMAKE_SHARED_LIBRARY_SUFFIX}/include)
  target_link_libraries(cose_dumper PRIVATE mbedtls)
else()
  # openssl
  target_include_directories(cose_dumper PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(cose_dumper PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(CLANG_TIDY_EXE)
  set_target_properties(cose_dumper PROPERTIES C_CLANG_TIDY "${CLANG_TIDY_EXE}")
endif()
