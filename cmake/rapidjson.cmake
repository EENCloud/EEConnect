include(ExternalProject)

add_library(rapidjson INTERFACE)

find_package(RapidJSON)
if(RapidJSON_FOUND)
  target_link_libraries(rapidjson INTERFACE RapidJSON::RapidJSON)
else()
  set(RAPIDJSON_VERSION 1.1.0)
  set(RAPIDJSON_SRCDIR ${CMAKE_CURRENT_BINARY_DIR}/rapidjson)

  ExternalProject_Add(rapidjson_sources
    URL https://github.com/Tencent/rapidjson/archive/v${RAPIDJSON_VERSION}.tar.gz
    URL_HASH SHA256=bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e
    SOURCE_DIR ${RAPIDJSON_SRCDIR}
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    )

  add_dependencies(rapidjson rapidjson_sources)
  set_target_properties(rapidjson PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${RAPIDJSON_SRCDIR}/include)
endif()
