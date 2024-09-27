set_project("benchmark")

add_rules("mode.release")

set_languages("c++17")

add_requires("benchmark", "jemalloc", "mimalloc", "gperftools")

if is_plat("windows") then
    add_cxxflags("/W4")
    if is_mode("release") then
        add_cxxflags("/O2")
    end
else
    add_cxxflags("-Wall", "-Wextra", "-Werror")
    if is_mode("release") then
        add_cxxflags("-O2")
    end
end

target("mtmalloc_benchmark")
    set_kind("binary")
    add_files("mtmalloc_benchmark.cpp")
    add_packages("benchmark")
    add_includedirs("..")

target("malloc_benchmark")
    set_kind("binary")
    add_files("malloc_benchmark.cpp")
    add_packages("benchmark")

target("jemalloc_benchmark")
    set_kind("binary")
    add_files("jemalloc_benchmark.cpp")
    add_packages("benchmark", "jemalloc")
    add_defines("JEMALLOC_NO_DEMANGLE")

target("mimalloc_benchmark")
    set_kind("binary")
    add_files("mimalloc_benchmark.cpp")
    add_packages("benchmark", "mimalloc")

target("tcmalloc_benchmark")
    set_kind("binary")
    add_files("tcmalloc_benchmark.cpp")
    add_packages("benchmark", "gperftools")
