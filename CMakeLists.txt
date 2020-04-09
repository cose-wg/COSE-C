cmake_minimum_required(VERSION 3.11)

set(VERSION_MAJOR
    0
    CACHE STRING "Project major version number")
set(VERSION_MINOR
    "1"
    CACHE STRING "Project minor version number")
set(VERSION_PATCH
    "0"
    CACHE STRING "Project patch version number")
set(COSE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
mark_as_advanced(VERSION_MAJOR VERSION_MINOR VERSION_PATCH COSE_VERSION)

project("cose-c" VERSION "${COSE_VERSION}")

###############################################################################
# OPTIONS
###############################################################################

option(optimize "Optimize for size" OFF)
option(coveralls "Generate coveralls data" ON)
option(coveralls_send "Send data to coveralls site" OFF)
option(include_encrypt "Include COSE_ENCRYPT" ON)
option(include_encrypt0 "Include COSE_ENCRYPT0" ON)
option(include_mac "Include COSE_MAC" ON)
option(include_mac0 "Include COSE_MAC0" ON)
option(include_sign "Include COSE_SIGN" ON)
option(include_sign0 "Include COSE_SIGN0" ON)
option(include_sign1 "Include COSE_SIGN1" ON)
option(COSE_C_USE_CONTEXT "Use context pointer for COSE functions" ON)
option(COSE_C_FATAL_WARNINGS "Treat build warnings as error" OFF)
option(COSE_C_BUILD_DOCS "Create docs using Doxygen" OFF)
option(COSE_C_BUILD_TESTS "build tests" ON)
option(COSE_C_USE_MBEDTLS "Use MBedTLS for the Crypto Package" OFF)
option(COSE_C_USE_PROJECT_ADD "download & build instead of using find_package for mbedtls and cn-cbor" ON)
option(COSE_C_BUILD_DUMPER "build dumper" ON)

# Set the output of the libraries and executables.
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX}/bin)
set(libdir ${CMAKE_INSTALL_PREFIX}/lib)
set(includedir ${CMAKE_INSTALL_PREFIX}/include)

if(NOT CMAKE_BUILD_TYPE)
  if(optimize)
    set(CMAKE_BUILD_TYPE MinSizeRel)
    set(coveralls OFF)
    set(coveralls_send OFF)
  else()
    message(STATUS "CMAKE_BUILD_TYPE empty setting to DEBUG")
    set(CMAKE_BUILD_TYPE "Debug")
  endif()
endif()

if(NOT include_encrypt)
  add_definitions(-DINCLUDE_ENCRYPT=0)
endif()
if(NOT include_encrypt0)
  add_definitions(-DINCLUDE_ENCRYPT0=0)
endif()
if(NOT include_mac)
  add_definitions(-DINCLUDE_MAC=0)
endif()
if(NOT include_mac0)
  add_definitions(-DINCLUDE_MAC0=0)
endif()
if(NOT include_sign)
  add_definitions(-DINCLUDE_SIGN=0)
endif()
if(NOT include_sign0 AND NOT include_sign1)
  add_definitions(-DINCLUDE_SIGN0=0)
endif()
if(COSE_C_USE_CONTEXT)
  add_definitions(-DUSE_CBOR_CONTEXT)
endif()

if(MSVC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(coveralls OFF)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

add_definitions(-DUSE_ARRAY)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(STATUS "adding GCC/Clang options ")
  add_definitions(-std=gnu99 -Wall -Wextra -pedantic)
  if(COSE_C_FATAL_WARNINGS)
    add_definitions(-Werror)
  endif()
  if(optimize)
    add_definitions(-Os)
  endif()
  add_definitions(-DNDEBUG)
elseif(MSVC)
  add_definitions(/W4)
  if(COSE_C_FATAL_WARNINGS)
    add_definitions(/WX)
  endif()
else()
  message(FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}")
endif()

###############################################################################
# DOCS
###############################################################################

if(COSE_C_BUILD_DOCS)
  find_package(Doxygen)
  if(NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "Doxygen is needed to build the documenation")
  endif()

  set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
  set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

  configure_file(${doxyfile_in} ${doxyfile} @ONLY)

  add_custom_target(
    doc
    COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM)

  install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
endif()

###############################################################################
# DEPENDENCIES
###############################################################################

if(COSE_C_USE_MBEDTLS)
  add_definitions(-DUSE_MBED_TLS)
  find_package(MbedTLS REQUIRED)
else()
  add_definitions(-DUSE_OPEN_SSL)
  find_package(OpenSSL REQUIRED)
endif()

include(FetchContent)

if(COSE_C_USE_PROJECT_ADD)
  fetchcontent_populate(
    project_cn_cbor
    GIT_REPOSITORY https://github.com/jimsch/cn-cbor
    GIT_TAG 1.0.0)
  set(optimize
      OFF
      CACHE BOOL "" FORCE)
  set(coveralls
      OFF
      CACHE BOOL "" FORCE)
  set(fatal_warnings
      OFF
      CACHE BOOL "" FORCE)
  add_subdirectory(${project_cn_cbor_SOURCE_DIR} ${project_cn_cbor_BINARY_DIR})
else()
  find_package(cn-cbor REQUIRED)
endif()

###############################################################################
# LIBRARY
###############################################################################

set(cose_sources
    src/crypto.h
    src/cose_int.h
    src/Cose.c
    src/MacMessage.c
    src/MacMessage0.c
    src/Sign.c
    src/Sign1.c
    src/cbor.c
    src/Encrypt.c
    src/Encrypt0.c
    src/Recipient.c
    src/SignerInfo.c
    src/mbedtls.c
    src/openssl.c)

add_library(${PROJECT_NAME} ${cose_sources})
target_link_libraries(${PROJECT_NAME} PUBLIC cn-cbor::cn-cbor)
target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src)

if(COSE_C_USE_MBEDTLS)
  target_include_directories(${PROJECT_NAME} PUBLIC ${MBEDTLS_INCLUDE_DIRS})
  target_link_libraries(${PROJECT_NAME} PUBLIC ${MBEDTLS_LIBRARIES})
else()
  target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(MSVC)
  target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()

if(COSE_C_BUILD_DUMPER)
  add_subdirectory(dumper)
endif()

###############################################################################
# TESTS
###############################################################################

if(coveralls)
  include(Coveralls)
  coveralls_turn_on_coverage()

  set(COVERAGE_SRC "")
  foreach(S ${cose_sources})
    get_filename_component(S_ABS ${S} ABSOLUTE)
    list(APPEND COVERAGE_SRCS ${S_ABS})
  endforeach()

  # Create the coveralls target. If we should upload
  coveralls_setup("${COVERAGE_SRCS}" ${coveralls_send})
endif()

if(COSE_C_BUILD_TESTS)
  include(CTest)
  add_subdirectory(test)
endif()

###############################################################################
# INSTALL
###############################################################################

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(COSE_C_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

configure_package_config_file(cmake/Config.cmake.in ${PROJECT_NAME}Config.cmake INSTALL_DESTINATION
                              ${COSE_C_CONFIG_INSTALL_DIR})
write_basic_package_version_file(${PROJECT_NAME}ConfigVersion.cmake COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  DESTINATION ${COSE_C_CONFIG_INSTALL_DIR}
  COMPONENT dev)
install(
  DIRECTORY include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h")

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin)
