cmake_minimum_required(VERSION 3.11.0)

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

option(COSE_C_USE_CONTEXT "Use context pointer for COSE functions" ON)
option(COSE_C_VERBOSE "Produce COSE_C_VERBOSE makefile output" OFF)
option(COSE_C_OPTIMIZE "Optimize for size" OFF)
option(COSE_C_FATAL_WARNINGS "Treat build warnings as error" OFF)
option(COSE_C_COVERALLS "Generate coveralls data" ON)
option(COSE_C_COVERALLS_SEND "Send data to coveralls site" OFF)
option(COSE_C_BUILD_DOCS "Create docs using Doxygen" OFF)
option(COSE_C_RUN_CLANG_TIDY "Use Clang-Tidy for static analysis" OFF)
option(COSE_C_BUILD_TESTS "build tests" ON)
option(COSE_C_BUILD_DUMPER "build dumper" ON)
option(BUILD_SHARED_LIBS "Build Shared Libraries" ON)
option(COSE_C_USE_MBEDTLS "Use MBedTLS for the Crypto Package" OFF)
option(COSE_C_USE_FIND_PACKAGE "Use cmake find_package instead of using cmake project_add" OFF)
option(COSE_C_INCLUDE_ENCRYPT "Include COSE_ENCRYPT" ON)
option(COSE_C_INCLUDE_ENCRYPT0 "Include COSE_ENCRYPT0" ON)
option(COSE_C_INCLUDE_MAC "Include COSE_MAC" ON)
option(COSE_C_INCLUDE_MAC0 "Include COSE_MAC0" ON)
option(COSE_C_INCLUDE_SIGN "Include COSE_SIGN" ON)
option(COSE_C_INCLUDE_SIGN1 "Include COSE_SIGN1" ON)
option(COSE_C_INCLUDE_COUNTERSIGN "Include COSE_COUNTERSIGN" OFF)
option(COSE_C_INCLUDE_COUNTERSIGN1 "Include COSE_COUNTERSIGN1" OFF)
option(COSE_C_VALGRIND_MEMORY_CHECK "use Valgrind to check memory, \
  run `ctest -D ExperimentalMemCheck` then after build to run tests with valgrind" OFF)

if(COSE_C_VALGRIND_MEMORY_CHECK)
  find_program(MEMORYCHECK_COMMAND valgrind)
  if(NOT MEMORYCHECK_COMMAND)
    message(FATAL_ERROR "valgrind not found.")
  endif()
  set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")
  set(MEMORYCHECK_SUPPRESSIONS_FILE "${PROJECT_SOURCE_DIR}/valgrind_suppress.txt")
endif()

set(COSE_C_USE_SANITIZER
    "none"
    CACHE
      STRING
      " \
    Name of the sanitizer which the user whats to use \
    This behaviour is the same is turning on one the sanitizer flags below \
    This option is a convenience option \
    ")
set_property(CACHE COSE_C_USE_SANITIZER PROPERTY STRINGS none address memory leak undefined)

set(COSE_C_USE_ADDRESS_SANITIZER OFF)
set(COSE_C_USE_MEMORY_SANITIZER OFF)
set(COSE_C_USE_LEAK_SANITIZER OFF)
set(COSE_C_USE_UNDEFINED_SANITIZER OFF)

if(COSE_C_USE_SANITIZER STREQUAL "address")
  set(COSE_C_USE_ADDRESS_SANITIZER ON)
endif()

if(COSE_C_USE_SANITIZER STREQUAL "memory")
  set(COSE_C_USE_MEMORY_SANITIZER ON)
endif()

if(COSE_C_USE_SANITIZER STREQUAL "leak")
  set(COSE_C_USE_LEAK_SANITIZER ON)
endif()

if(COSE_C_USE_SANITIZER STREQUAL "undefined")
  set(COSE_C_USE_UNDEFINED_SANITIZER ON)
endif()

# Set the output of the libraries and executables.
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

set(dist_dir ${CMAKE_BINARY_DIR}/dist)
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX}/bin)
set(libdir ${CMAKE_INSTALL_PREFIX}/lib)
set(includedir ${CMAKE_INSTALL_PREFIX}/include)

if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 11)
endif()

if(NOT CMAKE_BUILD_TYPE)
  if(COSE_C_OPTIMIZE)
    set(CMAKE_BUILD_TYPE MinSizeRel)
    set(COSE_C_COVERALLS OFF)
    set(COSE_C_COVERALLS_SEND OFF)
  else()
    set(CMAKE_BUILD_TYPE Debug)
  endif()
endif()

if(NOT COSE_C_INCLUDE_ENCRYPT)
  add_definitions(-DINCLUDE_ENCRYPT=0)
endif()
if(NOT COSE_C_INCLUDE_ENCRYPT0)
  add_definitions(-DINCLUDE_ENCRYPT0=0)
endif()
if(NOT COSE_C_INCLUDE_MAC)
  add_definitions(-DINCLUDE_MAC=0)
endif()
if(NOT COSE_C_INCLUDE_MAC0)
  add_definitions(-DINCLUDE_MAC0=0)
endif()
if(NOT COSE_C_INCLUDE_SIGN)
  add_definitions(-DINCLUDE_SIGN=0)
endif()
if(NOT COSE_C_INCLUDE_SIGN1)
  add_definitions(-DINCLUDE_SIGN1=0)
endif()
if(NOT COSE_C_INCLUDE_COUNTERSIGN)
  add_definitions(-DINCLUDE_COUNTERSIGN=0)
endif()
if(NOT COSE_C_INCLUDE_COUNTERSIGN1)
  add_definitions(-DINCLUDE_COUNTERSIGN1=0)
endif()
if(COSE_C_USE_CONTEXT)
  add_definitions(-DUSE_CBOR_CONTEXT)
endif()
if(MSVC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(COSE_C_COVERALLS OFF)
endif()

if(versbose)
  set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

# Control the order of packages - get the latest not the first
set(CMAKE_FIND_PACKAGE_SORT_ORDER NATURAL)
set(CMAKE_FIND_PACKAGE_SORT_DIRECTION DEC)

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
# STATIC ANALYSIS
###############################################################################

if(COSE_C_RUN_CLANG_TIDY)
  find_program(
    CLANG_TIDY_EXE
    NAMES "clang-tidy"
    DOC "/usr/bin/clang-tidy")
  if(NOT CLANG_TIDY_EXE)
    message(WARNING "clang-tidy not found.")
  endif()
endif(COSE_C_RUN_CLANG_TIDY)

include(sanitizers)

###############################################################################
# DEPENDENCIES
###############################################################################

if(COSE_C_USE_FIND_PACKAGE)
  find_package(cn-cbor)
else()
  include(FetchContent)

  fetchcontent_declare(
    project_cn_cbor
    GIT_REPOSITORY https://github.com/jimsch/cn-cbor.git
    GIT_TAG master)

  fetchcontent_getproperties(project_cn_cbor)
  if(NOT project_cn_cbor_POPULATED)
    fetchcontent_populate(project_cn_cbor)
    set(CN_CBOR_FATAL_WARNINGS
        OFF
        CACHE BOOL "" FORCE)
    set(CN_CBOR_COVERALLS
        OFF
        CACHE BOOL "" FORCE)
    set(CN_CBOR_USE_CONTEXT
        ${COSE_C_USE_CONTEXT}
        CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS
        ${BUILD_SHARED_LIBS}
        CACHE BOOL "" FORCE)
    set(CN_CBOR_BUILD_DOCS
        OFF
        CACHE BOOL "" FORCE)
    set(CN_CBOR_BUILD_TESTS
        OFF
        CACHE BOOL "" FORCE)
    add_subdirectory(${project_cn_cbor_SOURCE_DIR} ${project_cn_cbor_BINARY_DIR} EXCLUDE_FROM_ALL)
  endif()
endif()

if(BUILD_SHARED_LIBS)
  set(BUILD_STATIC_LIBS OFF)
else()
  set(BUILD_STATIC_LIBS ON)
endif()

if(COSE_C_USE_MBEDTLS)
  set(COSE_C_USE_OPENSSL OFF)

  if(COSE_C_USE_FIND_PACKAGE)
    find_package(MbedTLS)
  else()
    include(FetchContent)
    fetchcontent_declare(
      project_mbedtls
      GIT_REPOSITORY https://github.com/ARMmbed/mbedtls
      GIT_TAG master)

    fetchcontent_getproperties(project_mbedtls)
    if(NOT project_mbedtls_POPULATED)
      fetchcontent_populate(project_mbedtls)
      set(ENABLED_PROGRAMS
          OFF
          CACHE BOOL "" FORCE)
      set(USE_STATIC_MBEDTLS_LIBRARY
          ${BUILD_STATIC_LIBS}
          CACHE BOOL "" FORCE)
      set(USE_SHARED_MBEDTLS_LIBRARY
          ${BUILD_SHARED_LIBS}
          CACHE BOOL "" FORCE)
      set(ENABLE_TESTING
          OFF
          CACHE BOOL "" FORCE)
      add_subdirectory(${project_mbedtls_SOURCE_DIR} ${project_mbedtls_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
    # TODO: remove next line after https://github.com/ARMmbed/mbedtls/pull/2090
    include_directories("${project_mbedtls_SOURCE_DIR}/include")
  endif()
else()
  find_package(OpenSSL REQUIRED)
  set(COSE_C_USE_OPENSSL ON)
endif()

###############################################################################
# ADD LIBRARY
###############################################################################

add_subdirectory(src)

###############################################################################
# ADD DUMPER
###############################################################################

if(COSE_C_BUILD_DUMPER)
  add_subdirectory(dumper)
endif()

###############################################################################
# ADD TESTS
###############################################################################

if(COSE_C_BUILD_TESTS)
  enable_testing()
  include(CTest)
  add_subdirectory(test)
endif()

###############################################################################
# PRINT CONFIG
###############################################################################

message(STATUS "COSE_C_INCLUDE_ENCRYPT:..........${COSE_C_INCLUDE_ENCRYPT}")
message(STATUS "COSE_C_INCLUDE_ENCRYPT0:.........${COSE_C_INCLUDE_ENCRYPT0}")
message(STATUS "COSE_C_INCLUDE_MAC:..............${COSE_C_INCLUDE_MAC}")
message(STATUS "COSE_C_INCLUDE_MAC0:.............${COSE_C_INCLUDE_MAC0}")
message(STATUS "COSE_C_INCLUDE_SIGN:.............${COSE_C_INCLUDE_SIGN}")
message(STATUS "COSE_C_INCLUDE_SIGN1:............${COSE_C_INCLUDE_SIGN1}")
message(STATUS "COSE_C_INCLUDE_COUNTERSIGN:......${COSE_C_INCLUDE_COUNTERSIGN}")
message(STATUS "COSE_C_INCLUDE_COUNTERSIGN1:.....${COSE_C_INCLUDE_COUNTERSIGN1}")
message(STATUS "COSE_C_USE_CONTEXT:..............${COSE_C_USE_CONTEXT}")
message(STATUS "COSE_C_FATAL_WARNINGS:...........${COSE_C_FATAL_WARNINGS}")
message(STATUS "COSE_C_BUILD_TESTS:..............${COSE_C_BUILD_TESTS}")
message(STATUS "COSE_C_BUILD_DOCS:...............${COSE_C_BUILD_DOCS}")
message(STATUS "COSE_C_USE_MBEDTLS:..............${COSE_C_USE_MBEDTLS}")
message(STATUS "COSE_C_USE_FIND_PACKAGE:.........${COSE_C_USE_FIND_PACKAGE}")
message(STATUS "COSE_C_BUILD_DUMPER:.............${COSE_C_BUILD_DUMPER}")
message(STATUS "CMAKE_BUILD_TYPE:................${CMAKE_BUILD_TYPE}")
message(STATUS "BUILD_SHARED_LIBS:...............${BUILD_SHARED_LIBS}")
message(STATUS "COSE_VERSION:....................${COSE_VERSION}")
message(STATUS "CMAKE_VERSION:...................${CMAKE_VERSION}")
message(STATUS "CMAKE_C_COMPILER:................${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER:..............${CMAKE_CXX_COMPILER}")
message(STATUS "CLANG_TIDY_EXE:..................${CLANG_TIDY_EXE}")
message(STATUS "COSE_C_USE_SANITIZER:............${COSE_C_USE_SANITIZER}")
message(STATUS "COSE_C_USE_ADDRESS_SANITIZER:....${COSE_C_USE_ADDRESS_SANITIZER}")
message(STATUS "COSE_C_USE_MEMORY_SANITIZER:.....${COSE_C_USE_MEMORY_SANITIZER}")
message(STATUS "COSE_C_USE_LEAK_SANITIZER:.......${COSE_C_USE_LEAK_SANITIZER}")
message(STATUS "COSE_C_USE_UNDEFINED_SANITIZER:..${COSE_C_USE_UNDEFINED_SANITIZER}")
message(STATUS "COSE_C_VALGRIND_MEMORY_CHECK:....${COSE_C_VALGRIND_MEMORY_CHECK}")
if(COSE_C_USE_OPENSSL)
message(STATUS "OpenSSL .........................${OPENSSL_LIBRARIES}")
endif()
message(STATUS "project_cn_cbor_SOURCE_DIR:......${project_cn_cbor_SOURCE_DIR}")
message(STATUS "project_cn_cbor_BINARY_DIR:......${project_cn_cbor_BINARY_DIR}")
message(STATUS "project_mbedtls_SOURCE_DIR:......${project_mbedtls_SOURCE_DIR}")
message(STATUS "project_mbedtls_BINARY_DIR:......${project_mbedtls_BINARY_DIR}")
