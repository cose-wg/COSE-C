add_library(${PROJECT_NAME})

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

if(COSE_C_USE_MBEDTLS)
  target_link_libraries(${PROJECT_NAME} PRIVATE mbedtls)
else()
  target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(MSVC)
  target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()

if(CLANG_TIDY_EXE)
  set_target_properties(${PROJECT_NAME} PROPERTIES C_CLANG_TIDY "${DO_CLANG_TIDY}")
endif()

target_compile_options(
  ${PROJECT_NAME}
  PRIVATE $<$<OR:$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wextra>
          $<$<OR:$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wall>
          $<$<OR:$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wno-sign-compare>)

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
include(CMakePackageConfigHelpers)

set(COSE_C_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

install(
  TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}Targets
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lib
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT dev
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT lib)
install(
  EXPORT ${PROJECT_NAME}Targets
  DESTINATION "${COSE_C_CONFIG_INSTALL_DIR}"
  NAMESPACE ${PROJECT_NAME}::
  COMPONENT dev)

configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/Config.cmake.in ${PROJECT_NAME}Config.cmake
                              INSTALL_DESTINATION ${COSE_C_CONFIG_INSTALL_DIR})
write_basic_package_version_file(${PROJECT_NAME}ConfigVersion.cmake COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  DESTINATION ${COSE_C_CONFIG_INSTALL_DIR}
  COMPONENT dev)

install(
  DIRECTORY ${PROJECT_SOURCE_DIR}/include/cose
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h")
