cmake_minimum_required(VERSION 3.25.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(ac-tools)

add_executable(
  ${PROJECT_NAME}
  src/main.cpp
)

target_compile_features(
  ${PROJECT_NAME}
  PRIVATE
  cxx_std_23
)

target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE
  ntdll
)

target_compile_options(
  ${PROJECT_NAME}
  PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -fno-exceptions
  -fno-rtti
  -march=native
  -mtune=native
)

target_compile_definitions(
  ${PROJECT_NAME}
  PRIVATE
  NOMINMAX
  WIN32_LEAN_AND_MEAN
)
