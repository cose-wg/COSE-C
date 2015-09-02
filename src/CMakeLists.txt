#
#  compiling/installing sources for COSE-C
#

set ( cose_sources 
	Cose.c
	MacMessage.c
	openssl.c
	Sign.c
	cbor.c
	Encrypt.c
	Message.c
	Recipient.c
	SignerInfo.c
)

if (use_context)
    add_definitions(-DUSE_CBOR_CONTEXT)
endif()
add_library ( cose-c SHARED ${cose_sources} )

target_include_directories ( cose-c PRIVATE ../src )
target_include_directories ( cose-c PUBLIC ../../cn-cbor/implement/cn-cbor/include )
target_include_directories ( cose-c PUBLIC ../../../openssl/openssl-1.0.1h/include )


install ( TARGETS cose-c
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	RUNTIME DESTINATION bin)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
if (coveralls)
    ### include(Coveralls)
    ## coveralls_turn_on_coverage()

    set(COVERAGE_SRC "")
    foreach (S ${cose_srcs})
       get_filename_component(S_ABS ${S} ABSOLUTE)
       list (APPEND COVERAGE_SRCS ${S_ABS})
    endforeach()

    # Create the coveralls target.
    ## coveralls_setup(
    ##	"${COVERAGE_SRCS}"
  ##	${coveralls_send}	# If we should upload
   ## )
endif()

add_custom_target(size
  COMMAND echo "${CMAKE_BINARY_DIR}/src/CMakeFiles/cn-cbor.dir/cn-cbor.c.o"
  COMMAND size "${CMAKE_BINARY_DIR}/src/CMakeFiles/cn-cbor.dir/cn-cbor.c.o"
  COMMAND size -m "${CMAKE_BINARY_DIR}/src/CMakeFiles/cn-cbor.dir/cn-cbor.c.o"
  DEPENDS cn-cbor
COMMENT "Output the size of the parse routine")
