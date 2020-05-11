cmake_minimum_required(VERSION 3.8)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(/usr/lib/swipl/include /usr/include/libr ${CMAKE_SOURCE_DIR}/lib/xsb)
link_directories(/usr/lib/swipl/lib/x86_64-linux)
link_directories(${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include(CheckCXXCompilerFlag)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -pthread)

project (r2prolog)
set(SOURCE_FILES
  src/prolog.cpp
  src/core_r2prolog.cpp
  src/xsb/prolog.cpp
  src/xsb/prologimpl.cpp
  src/xsb/xsb.cpp
  )

add_library(${PROJECT_NAME} SHARED "${SOURCE_FILES}")
target_link_libraries(${PROJECT_NAME}
  swipl 
  xsb boost_filesystem 
  r_bin r_magic r_io r_socket r_syscall r_util)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "core_ppl")
