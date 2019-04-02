function(set_string_option OPT_NAME OPT_VALUE OPT_DESCRIPTION)
  set(${OPT_NAME} ${OPT_VALUE} CACHE STRING ${OPT_DESCRIPTION})

  list(APPEND BUILD_OPTIONS ${OPT_NAME})
  set(BUILD_OPTIONS "${BUILD_OPTIONS}" PARENT_SCOPE)
endfunction()

function(set_bool_option OPT_NAME OPT_VALUE OPT_DESCRIPTION)
  option(${OPT_NAME} ${OPT_DESCRIPTION} ${OPT_VALUE})

  list(APPEND BUILD_OPTIONS ${OPT_NAME})
  set(BUILD_OPTIONS "${BUILD_OPTIONS}" PARENT_SCOPE)
endfunction()

function(compile_build_options TARGET DEFINE_NAME)
  foreach (val ${BUILD_OPTIONS})
    set(ALL_OPTIONS "${val}=${${val}} ${ALL_OPTIONS}")
  endforeach()
  message(${ALL_OPTIONS})
  target_compile_definitions(${TARGET} PRIVATE ${DEFINE_NAME}="${ALL_OPTIONS}")
endfunction()
