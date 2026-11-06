cmake_minimum_required(VERSION 3.21)
project(reference_gateway VERSION 1.0.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
option(WITH_LZ4 "Build with the optional LZ4 codec" OFF)

find_package(ZLIB REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)

# Vendored source: invisible to Conan, declared through a component record.
add_library(tinycrc STATIC third_party/tinycrc/tinycrc.c)
target_include_directories(tinycrc PUBLIC third_party/tinycrc)

add_executable(gateway src/main.cpp)
target_link_libraries(gateway PRIVATE ZLIB::ZLIB fmt::fmt nlohmann_json::nlohmann_json tinycrc)

if(WITH_LZ4)
  find_package(lz4 REQUIRED)
  target_link_libraries(gateway PRIVATE LZ4::lz4_static)
  target_compile_definitions(gateway PRIVATE WITH_LZ4=1)
endif()

install(TARGETS gateway RUNTIME DESTINATION bin)
