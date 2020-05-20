if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(STATUS "adding GCC/Clang options ")
  add_definitions(-Wall -Wextra -pedantic)
  if(COSE_C_FATAL_WARNINGS)
    add_definitions(-Werror)
  endif()
  if(COSE_C_OPTIMIZE)
    add_definitions(-Os)
    add_definitions(-DNDEBUG)
  endif()
elseif(MSVC)
  add_definitions(/W4)
  if(COSE_C_FATAL_WARNINGS)
    add_definitions(/WX)
  endif()
  if(COSE_C_OPTIMIZE)
    add_definitions(-DNDEBUG)
  endif()
else()
  message(FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}")
endif()

add_library(${PROJECT_NAME})

# some structs look differently depending on the crypto lib used
# therefore we create the config header file at configure time.
configure_file(${CMAKE_CURRENT_LIST_DIR}/../include/cose/cose_configure.h.in
               ${CMAKE_BINARY_DIR}/include/cose/cose_configure.h)

if(COSE_C_USE_MBEDTLS)
  set(cose_crypto mbedtls.cpp)
else()
  set(cose_crypto openssl.cpp)
endif()

set(cose_sources
    ${PROJECT_SOURCE_DIR}/include/cose/cose.h
    ${CMAKE_BINARY_DIR}/include/cose/cose_configure.h
    cose_crypto.h
    cose_int.h
    Cose.cpp
    utils.hpp
    CoseKey.cpp
    CounterSign.cpp
    CounterSign1.cpp
    MacMessage.cpp
    MacMessage0.cpp
    Sign.cpp
    Sign1.cpp
    cbor.cpp
    Encrypt.cpp
    Encrypt0.cpp
    Recipient.cpp
    SignerInfo.cpp
    ${cose_crypto})

target_sources(${PROJECT_NAME} PRIVATE ${cose_sources})

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
         $<INSTALL_INTERFACE:include>
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
  set_target_properties(${PROJECT_NAME} PROPERTIES C_CLANG_TIDY "${CLANG_TIDY_EXE}")
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
include(CMakePackageConfigHelpers)

set(COSE_C_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

if(COSE_C_EXPORT_TARGETS)
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
endif()

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
install(
  DIRECTORY ${CMAKE_BINARY_DIR}/include/cose
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h")
