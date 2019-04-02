find_package(Git)

if(GIT_FOUND)
  execute_process(COMMAND ${GIT_EXECUTABLE} describe --always --dirty
    OUTPUT_VARIABLE GIT_DESCRIBE_VERSION)
  if(GIT_DESCRIBE_VERSION)
    string(STRIP ${GIT_DESCRIBE_VERSION} GIT_DESCRIBE_VERSION)
    set(GIT_DESCRIBE_VERSION_REGEX "^v([0-9]*)\.([0-9]*)\.([0-9]*)([a-zA-Z0-9_-]*)$")
    string(REGEX MATCH ${GIT_DESCRIBE_VERSION_REGEX} GIT_DESCRIBE_MATCH ${GIT_DESCRIBE_VERSION})
    if(NOT GIT_DESCRIBE_MATCH)
      message(WARNING "Wrong git describe version: ${GIT_DESCRIBE_VERSION}")
    else()
      string(REGEX REPLACE ${GIT_DESCRIBE_VERSION_REGEX}
        "\\1.\\2.\\3\\4" GIT_VERSION ${GIT_DESCRIBE_VERSION})
      string(REGEX REPLACE ${GIT_DESCRIBE_VERSION_REGEX}
        "\\1.\\2.\\3" GIT_BASE_VERSION ${GIT_DESCRIBE_VERSION})
      string(COMPARE EQUAL "${PROJECT_VERSION}" "${GIT_BASE_VERSION}" GIT_MATCH_PROJECT_VERSION)
      if(NOT GIT_MATCH_PROJECT_VERSION)
        message(WARNING "git base version (${GIT_BASE_VERSION}) does not match project version (${PROJECT_VERSION})")
      endif()
    endif()
  endif()
endif()
