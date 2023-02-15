# Objective
Demonstrate libbpf-based application development and modern C++ programming techniques
while developing a tool to characterize the sizes,
filesystem locations, and access patterns of an application's filesystem I/O.
Output from this tool may inform application optimization efforts,
advanced filesystem tuning, and the design of storage performance benchmarks.

## Target operating system
`bpf-iotrace` shall be compatible with any Linux host with libc6 v2.27 or later and a v4.14 or later kernel configured with eBPF.

## Implementation languages
* BPF probes shall be implemented in C and with critical functions implemented in BPF assembly as necessary.
* User-space code shall be implemented in C++ 17 and may be ported to Rust as a future project.

## Output
* Aggregate I/O statistics for instrumented applications shall be saved on a per-file basis in such a way that they can be analyzed individually or further aggregated across multiple files or directories.

### File identification
All files shall be identified by a combination of their mount namespace ID, (i.e. the output of `readlink /proc/<pid>/ns/mnt`), and their absolute path.  (This disambiguates files with the same paths opened in different containers.)

### Per-file metrics
`bpf-iotrace` shall record the following measurements and aggregate metrics for every file read from or written to by an instrumented application:
* Error count for each instrumented I/O system call
* Per-syscall read request size histogram
* Per-syscall completed read size histogram
* Per-syscall write request size histogram
* Per-syscall completed write size histogram
* Sequential completed read size histogram
* Sequential completed write size histogram
* Histogram of bytes written between `fsync()` calls
* Total bytes read
* Entry time for the first read system call
* Return time for the last successful read system call
* Total bytes written
* Total `fsync()`ed bytes
* Last `fsync()` time.
* Entry time for the first write system call
* Return time for the last successful write system call
* Re-write count, (Number of times a write was sent to the same file offset as the previous write.)
* `fsync()` latency histogram


## Instrumentation
`bpf-iotrace` shall include BPF instrumentation for the following system calls:
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

`bpf-iotrace` shall also include trace point and/or kprobe instrumentation necessary to track asynchronous I/O operations.

## Filtering
To maximize its signal-to-noise ratio, `bpf-iotrace` shall provide the following mechanisms for ignoring extraneous system calls:
* `bpf-iotrace` shall only trace system calls performing I/O operations on named, regular files.
* `bpf-iotrace` shall provide a mechanism to allow users to select a specific command, or set of commands, (as specified in `/proc/<pid>/comm`), that they wish to trace.
* `bpf-iotrace` shall provide a mechanism to allow users to select a specific process ID, or set of process IDs that they wish to trace

## TUI reporting
`bpf-iotrace` may be extended to include reporting and analysis via text-based user interface, (TUI).

## Time series I/O metrics? (Make optional)
`bpf-iotrace` may be extended to include time-series file I/O metrics

# References
* https://fio.readthedocs.io/en/latest/fio_doc.html