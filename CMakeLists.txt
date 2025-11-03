cmake_minimum_required(VERSION 3.10)
project(pexw_tools C)

add_executable(pexw pexw.c)

find_library(CAPSTONE_LIBRARY NAMES capstone)
find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)

if(CAPSTONE_LIBRARY AND CAPSTONE_INCLUDE_DIR)
  message(STATUS "Found Capstone library: ${CAPSTONE_LIBRARY}")
  message(STATUS "Found Capstone headers: ${CAPSTONE_INCLUDE_DIR}")

  add_executable(pexw_cross pexw_cross.c)
  target_include_directories(pexw_cross PRIVATE ${CAPSTONE_INCLUDE_DIR})
  target_link_libraries(pexw_cross ${CAPSTONE_LIBRARY})

  if(UNIX AND NOT APPLE)
    target_compile_options(pexw_cross PRIVATE -Wall -Wextra)
  elseif(APPLE)
    target_compile_options(pexw_cross PRIVATE -Wall -Wextra)
  endif()

  install(TARGETS pexw_cross DESTINATION bin)
else()
  message(WARNING "Capstone not found. Skipping pexw_cross build.")
  message(STATUS "Install with: apt-get install libcapstone-dev (Linux) or brew install capstone (macOS)")
endif()
