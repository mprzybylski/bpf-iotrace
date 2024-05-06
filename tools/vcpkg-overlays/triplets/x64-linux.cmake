set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/../../../.devcontainer/toolchain.cmake")

# List of LGPL-licensed dependencies AND transitive dependencies that must be dynamically linked to them.
set(LGPL_DEPENDENCIES elfutils bzip2)

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
# Force LGPL dependencies to be dynamically linked
if(PORT IN_LIST LGPL_DEPENDENCIES)
    set(VCPKG_LIBRARY_LINKAGE dynamic)
endif()

set(VCPKG_CMAKE_SYSTEM_NAME Linux)

