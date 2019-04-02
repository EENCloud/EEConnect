include(ExternalProject)

add_library(protobuf-c INTERFACE)

find_package(ProtobufC)
if(ProtobufC_FOUND)
  target_link_libraries(protobuf-c INTERFACE ProtobufC::ProtobufC)
else()
  set(PROTOBUFC_VERSION 1.3.1)
  set(PROTOBUFC_SRCDIR ${CMAKE_CURRENT_BINARY_DIR}/protobufc)

  ExternalProject_Add(protobufc_sources
    URL https://github.com/protobuf-c/protobuf-c/archive/v${PROTOBUFC_VERSION}.tar.gz
    URL_HASH SHA256=5eeec797d7ff1d4b1e507925a1780fad5dd8dd11163203d8832e5a9f20a79b08
    SOURCE_DIR ${PROTOBUFC_SRCDIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND "")

  add_custom_command(
    OUTPUT ${PROTOBUFC_SRCDIR}/protobuf-c/protobuf-c.c
    COMMAND ""
    DEPENDS protobufc_sources)

  add_library(protobufc_lib STATIC ${PROTOBUFC_SRCDIR}/protobuf-c/protobuf-c.c)
  target_compile_options(protobufc_lib
    PRIVATE -fdata-sections -ffunction-sections)
  target_link_libraries(protobuf-c INTERFACE protobufc_lib)
  set_target_properties(protobuf-c PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${PROTOBUFC_SRCDIR})
endif()
