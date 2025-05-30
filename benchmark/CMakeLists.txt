cmake_minimum_required(VERSION 3.10)
project(Benchmark)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(
    /W4 /permissive- /WX
    $<$<CONFIG:RELEASE>:/O2>
    $<$<CONFIG:RELEASE>:/fp:fast>
    $<$<CONFIG:DEBUG>:/Od>
  )
  add_link_options(
    $<$<CONFIG:RELEASE>:/LTCG>
  )
else()
  add_compile_options(
    -Wall -Wextra -Wpedantic -Werror -Wshadow
    $<$<CONFIG:RELEASE>:-O3>
    $<$<CONFIG:RELEASE>:-march=native>
    $<$<CONFIG:DEBUG>:-O0>
    $<$<CONFIG:DEBUG>:-g>
  )
  add_link_options(
    $<$<CONFIG:RELEASE>:-flto>
  )
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

find_package(Threads REQUIRED)
find_package(benchmark REQUIRED)

add_executable(mt_benchmark mt_benchmark.cpp)
target_link_libraries(mt_benchmark PRIVATE
    benchmark::benchmark
    Threads::Threads
)
add_executable(std_benchmark std_benchmark.cpp)
target_link_libraries(std_benchmark PRIVATE
    benchmark::benchmark
    Threads::Threads
)