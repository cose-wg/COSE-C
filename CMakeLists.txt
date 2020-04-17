cmake_minimum_required(VERSION 3.0.0)

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
option(COSE_C_INCLUDE_SIGN0 "Include COSE_SIGN0" ON)
option(COSE_C_INCLUDE_SIGN1 "Include COSE_SIGN1" ON)

if(NOT COSE_C_INCLUDE_SIGN0)
  message("Use COSE_C_INCLUDE_SIGN1 rather than COSE_C_INCLUDE_SIGN0")
  set(COSE_C_INCLUDE_SIGN1 ${COSE_C_INCLUDE_SIGN0})
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
if(COSE_C_USE_CONTEXT)
  add_definitions(-DUSE_CBOR_CONTEXT)
endif()
if(MSVC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(COSE_C_COVERALLS OFF)
endif()

message("Build type: ${CMAKE_BUILD_TYPE}")

add_definitions(-DUSE_ARRAY)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(STATUS "adding GCC/Clang options ")
  add_definitions(-std=gnu99 -Wall -Wextra -pedantic)
  if(COSE_C_FATAL_WARNINGS)
    add_definitions(-Werror)
  endif()
  if(COSE_C_OPTIMIZE)
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

set(LIB_TYPE STATIC)
if(BUILD_SHARED_LIBS)
  set(LIB_TYPE SHARED)
endif(BUILD_SHARED_LIBS)

if(versbose)
  set(CMAKE_VERBOSE_MAKEFILE ON)
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

if(COSE_C_USE_FIND_PACKAGE)
  find_package(cn-cbor REQUIRED)
else()
  include(ExternalProject)
  externalproject_add(
    project_cn-cbor
    GIT_REPOSITORY https://github.com/jimsch/cn-cbor
    GIT_TAG master
    CMAKE_ARGS -Doptimize=OFF
               -Duse_context=${COSE_C_USE_CONTEXT}
               -Dbuild_docs=OFF
               -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
               -Dcoveralls=OFF
               -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
               -Dfatal_warnings=OFF
    INSTALL_DIR "${dist_dir}"
    UPDATE_DISCONNECTED 1)

  externalproject_get_property(project_cn-cbor install_dir)
  include_directories("${install_dir}/include")

  if(MSVC)
    add_library(cn-cbor STATIC IMPORTED GLOBAL)
    set_property(TARGET cn-cbor PROPERTY IMPORTED_LOCATION
                                         "${install_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}cn-cbor.lib")
  else()
    add_library(cn-cbor STATIC IMPORTED GLOBAL)
    set_property(
      TARGET cn-cbor PROPERTY IMPORTED_LOCATION
                              "${install_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}cn-cbor${CMAKE_SHARED_LIBRARY_SUFFIX}")
  endif()

  if(NOT TARGET cn-cbor::cn-cbor)
    add_library(cn-cbor::cn-cbor ALIAS cn-cbor)
  endif()

  add_dependencies(cn-cbor project_cn-cbor)
endif()

if(COSE_C_USE_MBEDTLS)
  add_definitions(-DUSE_MBED_TLS)

  if(COSE_C_USE_FIND_PACKAGE)
    find_package(MbedTLS REQUIRED)
  else()
    externalproject_add(
      project_mbedtls
      GIT_REPOSITORY https://github.com/ARMmbed/mbedtls
      CMAKE_ARGS -DENABLED_PROGRAMS=OFF
                 -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
                 -Dcoveralls=OFF
                 -DUSE_SHARED_MBEDTLS_LIBRARY=${BUILD_SHARED_LIBS}
                 -Dfatal_warnings=OFF
                 -DENABLE_TESTING=OFF
                 -DLIB_INSTALL_DIR=${install_dir}/lib
                 INTALL_DIR
                 "${dist_dir}"
      UPDATE_DISCONNECTED 1)

    externalproject_get_property(project_mbedtls install_dir)
    include_directories("${install_dir}/include")
    add_library(mbedtls STATIC IMPORTED)
    if(MSVC)
      set_property(TARGET mbedtls PROPERTY IMPORTED_LOCATION
                                           "${dist_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}mbedcrypto.lib")
    else()
      set_property(
        TARGET mbedtls PROPERTY IMPORTED_LOCATION
                                "${dist_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}mbedcrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
    endif()
    add_dependencies(mbedtls project_mbedtls)
  endif()

else()
  find_package(OpenSSL REQUIRED)
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
message(STATUS "COSE_C_INCLUDE_SIGN0:............${COSE_C_INCLUDE_SIGN0}")
message(STATUS "COSE_C_INCLUDE_SIGN1:............${COSE_C_INCLUDE_SIGN1}")
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
