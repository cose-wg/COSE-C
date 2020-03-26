#
#  top level build file for COSE-C
#

## prepare CMAKE
cmake_minimum_required( VERSION 3.11)

set (VERSION_MAJOR 0 CACHE STRING "Project major version number")
set (VERSION_MINOR "1" CACHE STRING "Project minor version number")
set (VERSION_PATCH "0" CACHE STRING "Project patch version number")
set (COSE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
mark_as_advanced(VERSION_MAJOR VERSION_MINOR VERSION_PATCH COSE_VERSION)

project ("cose-c" VERSION "${COSE_VERSION}")

###############################################################################
# OPTIONS
###############################################################################

option (use_context              "Use context pointer for COSE functions" ON)
option (verbose                  "Produce verbose makefile output" OFF)
option (optimize                 "Optimize for size" OFF)
option (fatal_warnings           "Treat build warnings as error" OFF)
option (coveralls                "Generate coveralls data" ON)
option (coveralls_send           "Send data to coveralls site" OFF )
option (build_docs               "Create docs using Doxygen" OFF )
option (build_tests              "build tests" ON )
option (build_shared_libs        "Build Shared Libraries" ON)
option (use_embedtls             "Use MBedTLS for the Crypto Package" OFF)
option (include_encrypt          "Include COSE_ENCRYPT" ON)
option (include_encrypt0         "Include COSE_ENCRYPT0" ON)
option (include_mac              "Include COSE_MAC" ON)
option (include_mac0             "Include COSE_MAC0" ON)
option (include_sign             "Include COSE_SIGN" ON)
option (include_sign0            "Include COSE_SIGN0" ON)
option (COSE_C_USE_PROJECT_ADD   "download and build together with this script instead of using find_package for mbedtls and cn-cbor" ON )

set ( dist_dir          ${CMAKE_BINARY_DIR}/dist )
set ( prefix            ${CMAKE_INSTALL_PREFIX} )
set ( exec_prefix       ${CMAKE_INSTALL_PREFIX}/bin )
set ( libdir            ${CMAKE_INSTALL_PREFIX}/lib )
set ( includedir        ${CMAKE_INSTALL_PREFIX}/include )


if (NOT CMAKE_BUILD_TYPE)
   if (optimize)
      set ( CMAKE_BUILD_TYPE MinSizeRel )
      set ( coveralls OFF )
      set ( coveralls_send OFF )
   else()
      message(STATUS "CMAKE_BUILD_TYPE empty setting to DEBUG")
      set(CMAKE_BUILD_TYPE "Debug")
   endif ()
endif()

if (NOT include_encrypt)
   add_definitions( -DINCLUDE_ENCRYPT=0 )
endif ()
if (NOT include_encrypt0)
   add_definitions( -DINCLUDE_ENCRYPT0=0 )
endif ()
if (NOT include_mac)
   add_definitions( -DINCLUDE_MAC=0 )
endif ()
if (NOT include_mac0)
   add_definitions( -DINCLUDE_MAC0=0 )
endif ()
if (NOT include_sign)
   add_definitions( -DINCLUDE_SIGN=0 )
endif ()
if (NOT include_sign0)
   add_definitions( -DINCLUDE_SIGN0=0 )
endif ()
if(use_context)
  add_definitions(-DUSE_CBOR_CONTEXT)
endif()

if ( MSVC OR CMAKE_C_COMPILER_ID MATCHES "Clang" )
   set (coveralls OFF)
endif ()

message ( "Build type: ${CMAKE_BUILD_TYPE}" )

add_definitions( -DUSE_ARRAY )
if ( CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
     CMAKE_C_COMPILER_ID MATCHES "Clang")
   message ( STATUS "adding GCC/Clang options ")
   add_definitions( -std=gnu99 -Wall -Wextra -pedantic )
   if ( fatal_warnings )
      add_definitions( -Werror )
   endif ()
   if (optimize) 
      add_definitions( -Os )
   endif ()
   add_definitions( -DNDEBUG )
elseif (MSVC)
   add_definitions ( /W4 )
   if (fatal_warnings)
      add_definitions( /WX )
   endif ()
else ()
    message ( FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}" )
endif ()

if (verbose)
   set (CMAKE_VERBOSE_MAKEFILE ON)
endif ()

###############################################################################
# DOCS
###############################################################################

if (build_docs)
   find_package(Doxygen)
   if (NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen is needed to build the documenation")
   endif()

   set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
   set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

   configure_file(${doxyfile_in} ${doxyfile} @ONLY)

   add_custom_target(doc
       COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
       WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
       COMMENT "Generating API documentation with Doxygen"
       VERBATIM)

   install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc)
endif()

###############################################################################
# DEPENDENCIES
###############################################################################

Include(ExternalProject)
include(FetchContent)

if(COSE_C_USE_PROJECT_ADD)
   FetchContent_Populate(
   project_cn_cbor
   GIT_REPOSITORY https://github.com/jimsch/cn-cbor
   GIT_TAG complete)
   set(optimize
   OFF
   CACHE BOOL "" FORCE)
   set(coveralls
   OFF
   CACHE BOOL "" FORCE)
   add_subdirectory(${project_cn_cbor_SOURCE_DIR} ${project_cn_cbor_BINARY_DIR})
else()
   find_package(cn-cbor REQUIRED)
endif()

if (use_embedtls)
   add_definitions( -DUSE_MBED_TLS )
   if(COSE_C_USE_PROJECT_ADD)
      ExternalProject_Add(
      project_embedtls
      GIT_REPOSITORY https://github.com/ARMmbed/mbedtls
      CMAKE_ARGS -DENABLED_PROGRAMS=OFF -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR> -Dcoveralls=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=${build_shared_libs} -Dfatal_warnings=OFF -DENABLE_TESTING=OFF -DLIB_INSTALL_DIR=${install_dir}/lib
      INTALL_DIR "${dist_dir}"
      UPDATE_DISCONNECTED 1
      )

      ExternalProject_Get_Property(project_embedtls install_dir)
      include_directories( "${install_dir}/include" )
      add_library( embedtls STATIC IMPORTED)
      if (MSVC)
         set_property (TARGET embedtls PROPERTY IMPORTED_LOCATION "${dist_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}mbedcrypto.lib")
      else ()
         set_property (TARGET embedtls PROPERTY IMPORTED_LOCATION "${dist_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}mbedcrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
      endif ()
      add_dependencies(embedtls project_embedtls)
   else()
      find_package(MbedTLS REQUIRED)
   endif ()
else()
   find_package(OpenSSL REQUIRED)
endif()

###############################################################################
# LIBRARY
###############################################################################

add_subdirectory(src)
add_subdirectory(dumper)

###############################################################################
# TESTS
###############################################################################

if(build_tests)
   include (CTest)
   add_subdirectory(test)
endif()

###############################################################################
# INSTALL
###############################################################################

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(COSE_C_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

install(
  TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}Targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib)

install(
  EXPORT ${PROJECT_NAME}Targets
  DESTINATION ${COSE_C_CONFIG_INSTALL_DIR}
  NAMESPACE ${PROJECT_NAME}::
  COMPONENT dev)

configure_package_config_file(cmake/Config.cmake.in ${PROJECT_NAME}Config.cmake
                              INSTALL_DESTINATION ${COSE_C_CONFIG_INSTALL_DIR})
write_basic_package_version_file(${PROJECT_NAME}ConfigVersion.cmake
                                 COMPATIBILITY SameMajorVersion)
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
      TARGETS cose-c
      LIBRARY DESTINATION lib
      ARCHIVE DESTINATION lib
      RUNTIME DESTINATION bin)
       