cmake_minimum_required(VERSION 3.10)
project(pexw_tools C)

# pexw.c is Windows-only and causes build errors on other platforms
# Uncomment the following line if building on Windows with MSVC/MinGW:
# add_executable(pexw pexw.c)

# Find Capstone library for cross-platform build
find_library(CAPSTONE_LIBRARY NAMES capstone)
find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)

if(CAPSTONE_LIBRARY AND CAPSTONE_INCLUDE_DIR)
  message(STATUS "Found Capstone library: ${CAPSTONE_LIBRARY}")
  message(STATUS "Found Capstone headers: ${CAPSTONE_INCLUDE_DIR}")

  add_executable(pexw_cross pexw_cross.c)
  target_include_directories(pexw_cross PRIVATE ${CAPSTONE_INCLUDE_DIR})
  target_link_libraries(pexw_cross PRIVATE ${CAPSTONE_LIBRARY})

  if(UNIX AND NOT APPLE)
    target_compile_options(pexw_cross PRIVATE -Wall -Wextra)
  elseif(APPLE)
    target_compile_options(pexw_cross PRIVATE -Wall -Wextra)
  endif()

  install(TARGETS pexw_cross RUNTIME DESTINATION bin)
else()
  message(WARNING "Capstone not found. Skipping pexw_cross build.")
  if(WIN32)
    message(STATUS "On Windows, install Capstone via vcpkg: vcpkg install capstone:x64-windows")
    message(STATUS "Then configure with: cmake -DCMAKE_TOOLCHAIN_FILE=[path/to/vcpkg]/scripts/buildsystems/vcpkg.cmake ..")
  elseif(UNIX AND NOT APPLE)
    message(STATUS "On Linux, install with: sudo apt-get install libcapstone-dev (Debian/Ubuntu)")
    message(STATUS "Or: sudo dnf install capstone-devel (Fedora/RHEL)")
  elseif(APPLE)
    message(STATUS "On macOS, install with: brew install capstone")
  endif()
endif()
