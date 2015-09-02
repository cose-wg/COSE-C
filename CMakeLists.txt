#
#  top level build file for COSE-C
#

## prepare CMAKE
cmake_minimum_required( VERSION 3.0.0)

set (VERSION_MAJOR 0 CACHE STRING "Project major version number")
set (VERSION_MINOR "1" CACHE STRING "Project minor version number")
set (VERSION_PATCH "0" CACHE STRING "Project patch version number")
set (COSE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
mark_as_advanced(VERSION_MAJOR VERSION_MINOR VERSION_PATCH COSE_VERSION)

project ("cose-c" VERSION "${COSE_VERSION}")

find_package(Doxygen)

### setup options
option (use_context	"Use context pointer for COSE functions" ON)
option (verbose         "Produce verbose makefile output" OFF)
option (optimize        "Optimize for size" OFF)
option (fatal_warnings  "Treat build warnings as error" OFF)
option (coveralls       "Generate coveralls data" OFF)
option (build_docs      "Create docs using Doxygen" ${DOXYGEN_FOUND} )

set ( dist_dir          ${CMAKE_BINARY_DIR}/dist )
set ( prefix            ${CMAKE_INSTALL_PREFIX} )
set ( exec_prefix       ${CMAKE_INSTALL_PREFIX}/bin )
set ( libdir            ${CMAKE_INSTALL_PREFIX}/lib )
set ( includedir        ${CMAKE_INSTALL_PREFIX}/include )


if (NOT CMAKE_BUILD_TYPE)
   if (optimize)
      set ( CMAKE_BUILD_TYPE MinSizeRel )
      set ( coveralls OFF )
   else ()
      set ( CMAKE_BUILD_TYPE Debug)
   endif ()
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
elseif (MSVC)
   add_definitions ( /W4 )
   if (fatal_warnings)
      add_definitions( /WX )
   endif ()
else ()
   message ( FATAL_ERROR "unhandled compiler id: ${CMAKE_C_COMPILER_ID}" )
endif ()

if (versbose)
   set (CMAKE_VERBOSE_MAKEFILE ON)
endif ()

## include the parts
add_subdirectory(src)
add_subdirectory(test)

##  try for documentation
if (build_docs)
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

Include(ExternalProject)
ExternalProject_Add(
  project_cn-cbor
  GIT_REPOSITORY https://github.com/jimsch/cn-cbor/tree/PrettyPrint
  CMAKE_ARGS -Doptimize=OFF -Duse_context=ON -Dbuild_docs=OFF -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
  INSTALL_DIR "${dist_dir}"
  UPDATE_DISCONNECTED 1
)

ExternalProject_Get_Property(project_cn-cbor install_dir)
include_directories ( "${install_dir}/include" )
add_library (cn-cbor STATIC IMPORTED)
set_property (TARGET cn-cbor PROPERTY IMPORTED_LOCATION "${install_dir}/lib/${CMAKE_SHARED_MODULE_PREFIX}cn-cbor${CMAKE_SHARED_LIBRARY_SUFFIX}")
add_dependcies(cn-cbor project_cn-cbor)
