cmake_minimum_required(VERSION 3.28.1)

set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/.devcontainer/toolchain.cmake
        CACHE STRING "Dev container toolchain file")
set(VCPKG_FIXUP_ELF_RPATH ON)

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/tools/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")

if(NOT EXISTS ${CMAKE_TOOLCHAIN_FILE})
    # Initialize / update the vcpkg submodule
    execute_process(COMMAND git submodule update --init --depth 1 -- tools/vcpkg
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
            COMMAND_ERROR_IS_FATAL ANY)
endif()

project(
        bpf-iotrace
        VERSION 0.1.0
        DESCRIPTION "A libbpf-based utility for characterizing the sizes, filesystem locations, and access patterns of an application's filesystem I/O"
        HOMEPAGE_URL https://github.com/mprzybylski/bpf-iotrace/
        LANGUAGES C CXX
)

if(NOT BPF_COMPILER)
    # Path to `clang` in the dev container.
    # Override with -DBPF_COMPILER=... if configuring outside dev container.
    set(BPF_COMPILER /usr/lib/llvm/17/bin/clang)
endif()

# Pickup the header files installed by vcpkg
include_directories("${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
add_subdirectory(src)
