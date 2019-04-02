# Custom command to generate .{c,h} files from .proto
add_custom_command (
  OUTPUT packets.pb-c.h packets.pb-c.c
  COMMAND protoc-c --c_out=.
                   -I ${CMAKE_CURRENT_SOURCE_DIR}
                   ${CMAKE_CURRENT_SOURCE_DIR}/packets.proto
  COMMAND ${CMAKE_COMMAND} -E create_symlink . proto
  DEPENDS packets.proto)

# Add static library
add_library(proto STATIC packets.pb-c.c)
target_include_directories(proto INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(proto PUBLIC protobuf-c)
