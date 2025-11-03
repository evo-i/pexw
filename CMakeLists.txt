cmake_minimum_required(VERSION 3.10)
project(pexw_tools C)

# Build exactly one target per platform to avoid workflow confusion
if(WIN32)
  message(STATUS "Configuring Windows target: pexw")
  add_executable(pexw pexw.c)
  install(TARGETS pexw DESTINATION bin)
else()
  message(STATUS "Configuring non-Windows target: pexw_cross")
  find_library(CAPSTONE_LIBRARY NAMES capstone REQUIRED)
  find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h REQUIRED)

  add_executable(pexw_cross pexw_cross.c)
  target_include_directories(pexw_cross PRIVATE ${CAPSTONE_INCLUDE_DIR})
  target_link_libraries(pexw_cross ${CAPSTONE_LIBRARY})

  if(UNIX AND NOT APPLE)
    target_compile_options(pexw_cross PRIVATE -Wall -Wextra)
  elseif(APPLE)
    target_compile_options(pexw_cross PRIVATE -Wall -Wextra)
  endif()

  install(TARGETS pexw_cross DESTINATION bin)
endif()
