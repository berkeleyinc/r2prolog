cmake_minimum_required(VERSION 3.8)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
include_directories(/usr/lib/swipl/include /usr/include/libr /usr/include/capstone ${CMAKE_SOURCE_DIR}/lib/xsb)
link_directories(/usr/lib/swipl/lib/x86_64-linux/ ${CMAKE_SOURCE_DIR}/lib)
# find_package(Boost COMPONENTS system filesystem REQUIRED)
# include_directories(${Boost_INCLUDE_DIRS})
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
# set(CMAKE_CC_COMPILER "/usr/bin/clang")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

project (r2prolog)
set(SOURCE_FILES
  prolog.cpp
  core_r2prolog.cpp
  # xsb/prolog.cpp
  # xsb/prologimpl.cpp
  # xsb/xsb.cpp
  )
list(TRANSFORM SOURCE_FILES PREPEND ${CMAKE_SOURCE_DIR}/src/)


#add_executable(${PROJECT_NAME} "${SOURCE_FILES}")
add_library(${PROJECT_NAME} SHARED "${SOURCE_FILES}")
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_link_libraries(${PROJECT_NAME}
  pthread
  swipl 
  boost_filesystem
  -lr_core -lssl -lcrypto -lcapstone -lr_config -lr_debug -lr_bp -lr_egg -lr_asm -lr_lang -lr_parse -lr_fs -lr_anal -lr_reg -lr_syscall -lr_search -lr_cons -lr_crypto -lr_hash -lr_bin -lr_io -lr_socket -lr_magic -lr_flag -lr_util -ldl
  )
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "core_ppl")
