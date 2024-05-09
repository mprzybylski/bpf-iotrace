#include <stdint.h>
#include <sys/types.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

//TODO: create read entry and exit handlers that dump PID, comm, FD, size, and return value

struct sys_read_state {
    unsigned int fd;
    size_t count;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, struct sys_read_state);
} sys_read_state_map SEC(".maps");

struct sys_enter_read_tp_ctx {
//    /sys/kernel/debug/tracing/events/syscalls/sys_enter_read# cat format
//    name: sys_enter_read
//            ID: 748
//    format:
//            field:unsigned short common_type;	offset:0;	size:2;	signed:0;
//    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
//    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
//    field:int common_pid;	offset:4;	size:4;	signed:1;
//
//    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
//    field:unsigned int fd;	offset:16;	size:8;	signed:0;
//    field:char * buf;	offset:24;	size:8;	signed:0;
//    field:size_t count;	offset:32;	size:8;	signed:0;
    uint16_t common_type;
    uint8_t common_flags;
    uint8_t common_preempt_count;
    int32_t common_pid;
    int32_t syscall_nr;
    uint32_t pad;
    uint32_t fd;
    char * buf;
    uint64_t count;
} __attribute__((packed, aligned(1)));

SEC("tp/syscalls/sys_enter_read")
int handle_sys_enter_read(struct sys_enter_read_tp_ctx *ctx) {
    struct sys_read_state state = {ctx->fd, ctx->count};
    //TODO: minimize the number of helper calls and measure performance change.
//    bpf_probe_read_kernel(&state.fd, sizeof(int), &ctx->fd);
//    bpf_probe_read_kernel(&state.count, sizeof(size_t), &ctx->count);
    uint64_t tgid_pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sys_read_state_map, &tgid_pid, &state, BPF_NOEXIST);
    return 0;
}

struct sys_exit_read_tp_ctx {
//    /sys/kernel/debug/tracing/events/syscalls/sys_exit_read# cat format
//    name: sys_exit_read
//            ID: 747
//    format:
//            field:unsigned short common_type;	offset:0;	size:2;	signed:0;
//    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
//    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
//    field:int common_pid;	offset:4;	size:4;	signed:1;
//
//    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
//    field:long ret;	offset:16;	size:8;	signed:1;
    uint16_t common_type;
    uint8_t common_flags;
    uint8_t common_preempt_count;
    int32_t common_pid;
    int32_t syscall_nr;
    uint32_t pad;
    int64_t ret;
} __attribute__((packed, aligned(1)));

SEC("tp/syscalls/sys_exit_read")
int handle_sys_exit_read(struct sys_exit_read_tp_ctx *ctx) {
    uint64_t tgid_pid = bpf_get_current_pid_tgid();
    struct sys_read_state *read_state = bpf_map_lookup_elem(&sys_read_state_map, &tgid_pid);
    if(read_state) {
        int pid = (int)(tgid_pid >> 32);
        char comm[16];
        bpf_get_current_comm(&comm, 16);
        {
            const char fmt[] = "Captured read() syscall: comm: %s, fd: %u, count: %u, ";
            bpf_trace_printk((const char *)&fmt, sizeof(fmt), &comm, pid, read_state->count);
        }
        {
            const char fmt[] = "ret: %li\n";
            bpf_trace_printk((const char *)&fmt, sizeof(fmt), ctx->ret);
        }
    }
    return 0;
}