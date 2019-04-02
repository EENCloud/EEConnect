include(ExternalProject)

add_library(openssl INTERFACE)

find_package(OpenSSL COMPONENTS Crypto SSL)
if(OPENSSL_FOUND)
  target_link_libraries(openssl INTERFACE OpenSSL::Crypto OpenSSL::SSL)
else()
  set(OPENSSL_VERSION 1.0.2p)
  set(OPENSSL_SRCDIR ${CMAKE_CURRENT_BINARY_DIR}/openssl_static)
  string(TOUPPER "${CMAKE_BUILD_TYPE}" _BUILD_TYPE)

  ExternalProject_Add(openssl_static
    URL ftp://ftp.openssl.org/source/old/1.0.2//openssl-${OPENSSL_VERSION}.tar.gz
    URL_HASH SHA256=50a98e07b1a89eb8f6a99477f262df71c6fa7bef77df4dc83025a2845c827d00
    SOURCE_DIR ${OPENSSL_SRCDIR}
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ${OPENSSL_SRCDIR}/Configure
                      -DOPENSSL_NO_HEARTBEATS
                      no-dso
                      os/compiler:unknown
    COMMAND sed -i
      -e "s| build_tests||g"
      -e "s|CC= unknown|CC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1}|g"
      -e "s|^CFLAG=|CFLAG=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_BUILD_TYPE}} -fdata-sections -ffunction-sections|g"
      ${OPENSSL_SRCDIR}/Makefile
    BUILD_COMMAND make
    INSTALL_COMMAND ""
    )

  add_dependencies(openssl openssl_static)
  target_link_libraries(openssl
    INTERFACE ${OPENSSL_SRCDIR}/libssl.a
    INTERFACE ${OPENSSL_SRCDIR}/libcrypto.a)
  set_target_properties(openssl PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_SRCDIR}/include)
endif()
