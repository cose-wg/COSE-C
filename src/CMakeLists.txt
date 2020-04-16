include(GNUInstallDirs)

if (COSE_C_USE_MBEDTLS)
  set (cose_crypto mbedtls.c)
else ()
  set (cose_crypto openssl.c)
endif()

set(cose_sources
  ${CMAKE_CURRENT_LIST_DIR}/../include/cose/cose.h
  ${CMAKE_CURRENT_LIST_DIR}/../include/cose/cose_configure.h
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
  ${cose_crypto}
)


if (COSE_C_USE_CONTEXT)
    add_definitions(-DUSE_CBOR_CONTEXT)
endif()

add_library ( cose-c ${LIB_TYPE} ${cose_sources} )

target_include_directories ( cose-c PRIVATE ${OPENSSL_INCLUDE_DIR} )
target_include_directories ( cose-c PUBLIC ${dist_dir}/include )
target_include_directories ( cose-c PUBLIC ../include )
target_include_directories ( cose-c PRIVATE ../src )

target_link_libraries ( cose-c PRIVATE ${OPENSSL_LIBRARIES} )
target_link_libraries ( cose-c PRIVATE cn-cbor )
if (COSE_C_USE_MBEDTLS)
    target_include_directories ( cose-c PUBLIC ${CMAKE_SHARED_MODLE_PREFIX}mbedtls${CMAKE_SHARED_LIBRARY_SUFFIX}/include )
    target_link_libraries ( cose-c PRIVATE mbedtls )
endif()

if ( MSVC )
    target_link_libraries( cose-c PRIVATE ws2_32 )
endif ()

install ( TARGETS cose-c
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	RUNTIME DESTINATION bin)
install(
  DIRECTORY ../include
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h")

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
if (COSE_C_COVERALLS)
    include(Coveralls)
    coveralls_turn_on_coverage()

    set(COVERAGE_SRC "")
    foreach (S ${cose_sources})
       get_filename_component(S_ABS ${S} ABSOLUTE)
       list (APPEND COVERAGE_SRCS ${S_ABS})
    endforeach()

    # Create the coveralls target.
    coveralls_setup(
    	"${COVERAGE_SRCS}"
  	${COSE_C_COVERALLS_SEND}	# If we should upload
    )
endif()
