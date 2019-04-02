# FindProtobufC.cmake
#
# Finds the protobuf-c library
#
# This will define the following variables
#
#    ProtobufC_FOUND
#    ProtobufC_INCLUDE_DIRS
#
# and the following imported targets
#
#     ProtobufC::ProtobufC
#

find_package(PkgConfig)
pkg_check_modules(PC_ProtobufC QUIET ProtobufC)

find_path(ProtobufC_INCLUDE_DIR
  NAMES protobuf-c.h
  PATHS ${PC_ProtobufC_INCLUDE_DIRS}
  PATH_SUFFIXES protobuf-c
  )

find_library(ProtobufC_LIBRARY
  NAMES
    protobuf-c
  PATH_SUFFIXES
    lib)

mark_as_advanced(ProtobufC_FOUND ProtobufC_INCLUDE_DIR
  ProtobufC_LIBRARY ProtobufC_VERSION)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ProtobufC
  REQUIRED_VARS ProtobufC_INCLUDE_DIR ProtobufC_LIBRARY
  VERSION_VAR ProtobufC_VERSION
)

if(ProtobufC_FOUND)
  set(ProtobufC_INCLUDE_DIRS ${ProtobufC_INCLUDE_DIR})
  set(ProtobufC_LIBRARIES ${ProtobufC_LIBRARY})
endif()

if(ProtobufC_FOUND AND NOT TARGET ProtobufC::ProtobufC)
  add_library(ProtobufC::ProtobufC UNKNOWN IMPORTED)
  set_target_properties(ProtobufC::ProtobufC PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ProtobufC_INCLUDE_DIR}")
  set_target_properties(ProtobufC::ProtobufC PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${ProtobufC_LIBRARY}")
endif()
