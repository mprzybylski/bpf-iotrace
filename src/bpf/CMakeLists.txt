if(NOT BPF_COMPILER)
    # Path to `clang` in the dev container.
    # Override with -DBPF_COMPILER=... if configuring outside dev container.
    set(BPF_COMPILER /usr/lib/llvm/17/bin/clang)
endif()

set(CMAKE_C_COMPILER "${BPF_COMPILER}")

# NOTES:
# - "-target bpf" is how we get clang to generate BPF code.
# - Some compiler warnings like failure to unroll a loop will break
#   a BPF program.  So we will treat every warning as an error (-Werror)
#   by default.
# - Include source-level debug info in generated objects (-G)
# - Optimization level 2 (-O2)
set(CMAKE_C_FLAGS "-target bpf -Werror -g -O2")

list(APPEND BPF_OBJECT_TARGETS read)

foreach (TARGET IN LISTS BPF_OBJECT_TARGETS)
    add_library(${TARGET} OBJECT ${TARGET}.c )
    list(APPEND BPF_OBJECT_LIBS $<TARGET_OBJECTS:${TARGET}>)
endforeach ()

add_custom_command(OUTPUT combined_bpf_lib.o
        COMMAND bpftool gen object combined_bpf_lib.o ${BPF_OBJECT_LIBS}
        DEPENDS ${BPF_OBJECT_LIBS}
        VERBATIM)

# TODO: strip all debugging symbols except BTF for releases

add_custom_command(OUTPUT bpf-skeleton.h
        COMMAND bpftool gen skeleton combined_bpf_lib.o > bpf-skeleton.h
        DEPENDS combined_bpf_lib.o
        VERBATIM)

add_custom_target(bpf_skeleton DEPENDS bpf-skeleton.h)