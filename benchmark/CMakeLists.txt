cmake_minimum_required(VERSION 3.10)
project(Benchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if (MSVC)
    add_compile_options(/O2 /fp:fast /W4 /WX)
    add_link_options(/LTCG)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-O3 -march=native -pipe -Wall -Wextra -Wpedantic -Werror)
    add_link_options(-flto)
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