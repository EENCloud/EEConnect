cmake_minimum_required(VERSION 3.4)
project(PNPclient VERSION 1.0.0)

include(cmake/options.cmake)

set_bool_option(CLIENT ON  "Build client application")
set_bool_option(SERVER OFF "Build server application")
set_bool_option(DBUS   OFF "Build application with DBUS")
set_string_option(LOGGER "stderr" "Log sink")
set_string_option(CONFIG_DIR "/etc/eeconnect" "Location of configuration files")
set(EMBED_CLIENT_DIR  ${PROJECT_SOURCE_DIR}/client_confs CACHE STRING
  "Directory with files to embed as static structures into client binary")
set(EMBED_SERVER_DIR  ${PROJECT_SOURCE_DIR}/server_confs CACHE STRING
  "Directory with files to embed as static structures into server binary")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(cmake/embed.cmake)
include(cmake/libmnl.cmake)
include(cmake/openssl_static.cmake)
include(cmake/protobufc.cmake)
include(cmake/rapidjson.cmake)
include(cmake/gitversion.cmake)
if(DBUS)
  find_package(GTK2 REQUIRED COMPONENTS gtk)
endif()

# Add subdirectories
add_subdirectory(src)
add_subdirectory(proto)
