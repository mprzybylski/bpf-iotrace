# Objective
`bpf-iotrace` shall characterize the sizes, filesystem locations, and access patterns of an application's filesystem I/O to inform application optimizations, advanced filesystem tuning, and storage performance benchmarks.

## Implementation languages
* BPF probes shall be implemented in C and with critical functions implemented in BPF assembly as necessary.
* User-space code shall be implemented in C++ 17 and may be ported to Rust as a future project.

## Output
I/O statistics for instrumented applications shall be saved on a per-file basis in such a way that they can be analyzed individually or aggregated across multiple files or directories.

### Per-file metrics
`bpf-iotrace` shall record the following measurements and aggregate metrics for every file read from or written to by an instrumented application:
* Call count for each instrumented I/O system call
* Error count for each instrumented I/O system call
* Per-syscall read request size histogram
* Per-syscall completed read size histogram
* Per-syscall write request histogram
* Per-syscall completed write size histogram
* Sequential completed read size histogram
* Sequential completed write size histogram
* Total bytes read
* Entry time for the first read system call
* Return time for the last successful read system call
* Total bytes written
* Entry time for the first write system call
* Return time for the last successful write system call
* Re-write count, (Number of times a write was sent to the same file offset as the previous write.)
* `fsync()` latency histogram
* `fsync()` total 

## Filtering
To maximize its signal-to-noise ratio, `bpf-iotrace` shall provide the following mechanisms for ignoring extraneous system calls:
* `bpf-iotrace` shall only trace system calls performing I/O operations on named, regular files.
* `bpf-iotrace` shall provide a mechanism to allow users to select a specific command, or set of commands, (as specified in `/proc/<pid>/comm`), that they wish to trace.
* `bpf-iotrace` shall provide a mechanism to allow users to select a specific process ID, or set of process IDs that they wish to trace

## System calls
`bpf-iotrace` shall include BPF handler programs for the following system calls:
* `close()`
* `fsync()`
* `sendfile()`
* `pread64()`
* `preadv()`
* `preadv2()`
* `read()`
* `readv()`
* `pwrite64()`
* `pwritev()`
* `pwritev2()`
* `write()`
* `writev()`

## TUI reporting
`bpf-iotrace` may be extended to include reporting and analysis via text-based user interface, (TUI).

## Time series I/O metrics? (Make optional)
`bpf-iotrace` may be extended to include time-series file I/O metrics

# References
* https://fio.readthedocs.io/en/latest/fio_doc.html#interpreting-the-output