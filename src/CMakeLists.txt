add_library(${PROJECT_NAME} ${LIB_TYPE})

if(COSE_C_USE_MBEDTLS)
  set(cose_crypto mbedtls.c)
else()
  set(cose_crypto openssl.c)
endif()

set(cose_sources
    ${PROJECT_SOURCE_DIR}/include/cose/cose.h
    ${PROJECT_SOURCE_DIR}/include/cose/cose_configure.h
    crypto.h
    cose_int.h
    crypto.h
    Cose.c
    MacMessage.c
    MacMessage0.c
    Sign.c
    Sign1.c
    cbor.c
    Encrypt.c
    Encrypt0.c
    Recipient.c
    SignerInfo.c
    ${cose_crypto})

target_sources(${PROJECT_NAME} PRIVATE ${cose_sources})

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE ../src)
target_link_libraries(${PROJECT_NAME} PRIVATE cn-cbor::cn-cbor)
# target_include_directories(${PROJECT_NAME} PUBLIC ${dist_dir}/include)

if(COSE_C_USE_MBEDTLS)
  target_include_directories(${PROJECT_NAME}
                             PUBLIC ${CMAKE_SHARED_MODLE_PREFIX}mbedtls${CMAKE_SHARED_LIBRARY_SUFFIX}/include)
  target_link_libraries(${PROJECT_NAME} PRIVATE mbedtls)
else()
  target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(MSVC)
  target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

if(COSE_C_COVERALLS)
  include(Coveralls)
  coveralls_turn_on_coverage()

  set(COVERAGE_SRC "")
  foreach(S ${cose_sources})
    get_filename_component(S_ABS ${S} ABSOLUTE)
    list(APPEND COVERAGE_SRCS ${S_ABS})
  endforeach()

  # Create the coveralls target. If we should upload
  coveralls_setup("${COVERAGE_SRCS}" ${COSE_C_COVERALLS_SEND})
endif()

###############################################################################
#INSTALL LIBRARY
###############################################################################

include(GNUInstallDirs)

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION lib COMPONENT lib
  ARCHIVE DESTINATION lib COMPONENT dev
  RUNTIME DESTINATION lib COMPONENT lib)
install(
  DIRECTORY ${PROJECT_SOURCE_DIR}/include/cose
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h")
