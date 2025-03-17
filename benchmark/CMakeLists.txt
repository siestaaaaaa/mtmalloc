cmake_minimum_required(VERSION 3.10)
project(Benchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -march=native")

find_package(Threads REQUIRED)
find_package(benchmark REQUIRED)

get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} DIRECTORY)
include_directories(${PARENT_DIR})

add_executable(mt_benchmark mt_benchmark.cpp)
target_link_libraries(mt_benchmark 
    PRIVATE 
    benchmark::benchmark 
    Threads::Threads
)
add_executable(std_benchmark std_benchmark.cpp)
target_link_libraries(std_benchmark 
    PRIVATE 
    benchmark::benchmark 
    Threads::Threads
)