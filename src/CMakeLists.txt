add_library(pnp STATIC
  pnp_address.c
  pnp_buffer.c
  pnp_channel.c
  pnp_cmd.c
  pnp_configuration.c
  pnp_connection.c
  pnp_connection_proxy.c
  pnp_hwaddr.c
  pnp_io_plain.c
  pnp_io_ssl.c
  pnp_mapport.c
  pnp_server_addresses.c
  pnp_protobuf_utils.c
  )

# Version from git
if(GIT_VERSION)
  set(EECONNECT_VERSION ${GIT_VERSION})
else()
  set(EECONNECT_VERSION ${PROJECT_VERSION})
endif()
message("EEConnect version ${EECONNECT_VERSION}")

target_compile_options(pnp PUBLIC
  -Wall -Werror -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
target_link_libraries(pnp PRIVATE libmnl proto pthread)
target_link_libraries(pnp PUBLIC openssl rapidjson)
target_include_directories(pnp PRIVATE ${EMBED_INCLUDE_DIRECTORY})

if(LOGGER STREQUAL "stderr")
  target_compile_definitions(pnp PUBLIC PNP_STDERR)
elseif(LOGGER STREQUAL "stdout")
  target_compile_definitions(pnp PUBLIC PNP_STDOUT)
elseif(LOGGER STREQUAL "syslog")
  target_compile_definitions(pnp PUBLIC PNP_SYSLOG)
endif()

target_compile_definitions(pnp PUBLIC $<$<CONFIG:Debug>:PNP_DEBUG>)
target_compile_options(pnp PRIVATE -fdata-sections -ffunction-sections)
target_compile_definitions(pnp PRIVATE EECONNECT_VERSION="${EECONNECT_VERSION}")

if(CLIENT)
  build_embed_lib(embed_client ${EMBED_CLIENT_DIR})
  set(CLIENT_NAME eeconnect)

  add_executable(${CLIENT_NAME} client.c client_config.cpp)
  target_link_libraries(${CLIENT_NAME} PRIVATE pnp embed_client)
  target_compile_definitions(${CLIENT_NAME} PRIVATE -DCONFIG_DIR="${CONFIG_DIR}")
  target_compile_definitions(${CLIENT_NAME} PRIVATE EECONNECT_VERSION="${EECONNECT_VERSION}")
  target_link_libraries(${CLIENT_NAME} PRIVATE
    -Wl,--as-needed -Wl,--gc-sections)
  install(TARGETS ${CLIENT_NAME} DESTINATION bin)

  if(DBUS)
    target_compile_definitions(${CLIENT_NAME} PRIVATE DBUS_ENABLED)
    target_sources(${CLIENT_NAME} PRIVATE pnp_dbus.c)
    target_link_libraries(${CLIENT_NAME} PRIVATE GTK2::glib GTK2::gio)

    install(FILES ../nl.een.${CLIENT_NAME}.conf DESTINATION /etc/dbus-1/system.d/)
  endif()
  compile_build_options(${CLIENT_NAME} BUILD_OPTIONS)
endif()

if(SERVER)
  build_embed_lib(embed_server ${EMBED_SERVER_DIR})
  set(SERVER_NAME eeserver)

  add_executable(${SERVER_NAME} server.c server_config.cpp)
  target_link_libraries(${SERVER_NAME} PRIVATE pnp pthread embed_server)
  target_compile_definitions(${SERVER_NAME} PRIVATE -DCONFIG_DIR="${CONFIG_DIR}")
  target_link_libraries(${SERVER_NAME} PRIVATE
    -Wl,--as-needed -Wl,--gc-sections)
  install(TARGETS ${SERVER_NAME} DESTINATION bin)
endif()
