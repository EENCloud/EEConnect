# Helper function to build library from generated source file
# containing files structures. This function embed all
# files from given directory (argument EMBED_DIR). Main library
# source file is generated by "embed.py" script which has to be
# run with python.
#
# Example:
#
#   build_embed_lib(embed home/user/configs)
#
set(EMBED_INCLUDE_DIRECTORY ${PROJECT_SOURCE_DIR}/tools/embed)

function(build_embed_lib LIB_NAME EMBED_DIR)
  # Add static library
  add_library(${LIB_NAME} STATIC ${LIB_NAME}_data.c)
  target_include_directories(${LIB_NAME}
    INTERFACE ${EMBED_INCLUDE_DIRECTORY})
  target_compile_options(${LIB_NAME}
    PRIVATE -fdata-sections -ffunction-sections)

  # Check if given EMBED_DIR even exists
  if(NOT IS_DIRECTORY ${EMBED_DIR})
    message(FATAL_ERROR "Directory ${EMBED_DIR} does not exist")
  endif()

  # Copy contents of directory to temporary dir
  file(GLOB FILES_TO_COPY ${EMBED_DIR}/*)
  add_custom_target(tmp_${LIB_NAME}
    COMMAND cp ${EMBED_DIR}/* ${CMAKE_CURRENT_BINARY_DIR})
  add_dependencies(${LIB_NAME} tmp_${LIB_NAME})

  # Retrieve naked file names from full file paths
  foreach(FILEPATH ${FILES_TO_COPY})
    get_filename_component(FILENAME ${FILEPATH} NAME)
    set(FILES_TO_EMBED ${FILES_TO_EMBED} ${FILENAME})
  endforeach()

  # Generate '*_data.c' file containing embedded static structures
  add_custom_command(
    OUTPUT  ${LIB_NAME}_data.c
    COMMAND python ${PROJECT_SOURCE_DIR}/tools/embed/embed.py
            ${FILES_TO_EMBED} > ${LIB_NAME}_data.c)
endfunction()
