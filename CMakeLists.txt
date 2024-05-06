cmake_minimum_required(VERSION 3.28.1)

set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/.devcontainer/toolchain.cmake
        CACHE STRING "Dev container toolchain file")
set(VCPKG_FIXUP_ELF_RPATH ON)

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/tools/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")

project(
        bpf-iotrace
        VERSION 0.1.0
        DESCRIPTION "A libbpf-based utility for characterizing the sizes, filesystem locations, and access patterns of an application's filesystem I/O"
        HOMEPAGE_URL https://github.com/mprzybylski/bpf-iotrace/
        LANGUAGES C CXX
)




