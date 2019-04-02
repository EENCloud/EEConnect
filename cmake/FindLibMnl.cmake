# FindLibMnl.cmake
#
# Finds the libmnl library
#
# This will define the following variables
#
#    LibMnl_FOUND
#    LibMnl_INCLUDE_DIRS
#
# and the following imported targets
#
#     LibMnl::LibMnl
#

find_package(PkgConfig)
pkg_check_modules(PC_LibMnl QUIET libmnl)

find_path(LibMnl_INCLUDE_DIR
  NAMES libmnl.h
  PATHS ${PC_LibMnl_INCLUDE_DIRS}
  PATH_SUFFIXES libmnl
  )

find_library(LibMnl_LIBRARY
  NAMES
    mnl
  PATHS
    ${PC_LibMnl_LIBRARY_DIRS}
  PATH_SUFFIXES
    lib)

mark_as_advanced(LibMnl_FOUND LibMnl_INCLUDE_DIR
  LibMnl_LIBRARY LibMnl_VERSION)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibMnl
  REQUIRED_VARS LibMnl_INCLUDE_DIR LibMnl_LIBRARY
  VERSION_VAR LibMnl_VERSION
)

if(LibMnl_FOUND)
  set(LibMnl_INCLUDE_DIRS ${LibMnl_INCLUDE_DIR})
  set(LibMnl_LIBRARIES ${LibMnl_LIBRARY})
endif()

if(LibMnl_FOUND AND NOT TARGET LibMnl::LibMnl)
  add_library(LibMnl::LibMnl UNKNOWN IMPORTED)
  set_target_properties(LibMnl::LibMnl PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${LibMnl_INCLUDE_DIR}")
  set_target_properties(LibMnl::LibMnl PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${LibMnl_LIBRARY}")
endif()
