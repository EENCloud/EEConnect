include(ExternalProject)

add_library(libmnl INTERFACE)

find_package(LibMnl)
if(LIBMNL_FOUND)
  target_link_libraries(libmnl INTERFACE LibMnl::LibMnl)
else()
  set(LIBMNL_VERSION 1.0.4)
  set(LIBMNL_SRCDIR ${CMAKE_CURRENT_BINARY_DIR}/libmnl_static)
  string(TOUPPER "${CMAKE_BUILD_TYPE}" _BUILD_TYPE)

  ExternalProject_Add(libmnl_static
    URL ftp://ftp.netfilter.org/pub/libmnl/libmnl-${LIBMNL_VERSION}.tar.bz2
    URL_HASH SHA256=171f89699f286a5854b72b91d06e8f8e3683064c5901fb09d954a9ab6f551f81
    SOURCE_DIR ${LIBMNL_SRCDIR}
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ${LIBMNL_SRCDIR}/configure
      "CC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1}"
      "CFLAGS=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_BUILD_TYPE}} -fdata-sections -ffunction-sections"
      --host=generic-unknown-linux
      --enable-static
      --disable-shared
    BUILD_COMMAND make
    INSTALL_COMMAND ""
    )

  add_dependencies(libmnl libmnl_static)
  target_link_libraries(libmnl
    INTERFACE ${LIBMNL_SRCDIR}/src/.libs/libmnl.a)
  set_target_properties(libmnl PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${LIBMNL_SRCDIR}/include)
endif()
