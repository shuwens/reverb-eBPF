#!/usr/bin/env python3
#
# MinIO eBPF Trace - Traces S3 operations in MinIO server
# This traces HTTP requests and disk I/O operations for MinIO

from bcc import BPF
from time import strftime
import ctypes as ct

# eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct http_data_t {
    u64 ts;
    u32 pid;
    char comm[16];
    char method[8];
    char path[128];
    u64 latency_ns;
    int status_code;
};

struct io_data_t {
    u64 ts;
    u32 pid;
    char comm[16];
    char filename[64];
    u64 offset;
    u64 size;
    char op[8];
    u64 latency_ns;
};

BPF_HASH(http_start, u64);
BPF_HASH(io_start, u64);
BPF_PERF_OUTPUT(http_events);
BPF_PERF_OUTPUT(io_events);

// Trace HTTP handler functions in MinIO
int trace_http_handler_start(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    
    http_start.update(&pid_tgid, &ts);
    return 0;
}

int trace_http_handler_end(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *tsp = http_start.lookup(&pid_tgid);
    
    if (tsp == 0) {
        return 0;
    }
    
    struct http_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = pid_tgid >> 32;
    data.latency_ns = data.ts - *tsp;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // In real implementation, you'd parse HTTP request details
    // This is a simplified example
    __builtin_memcpy(&data.method, "GET", 4);
    __builtin_memcpy(&data.path, "/bucket/object", 15);
    data.status_code = PT_REGS_RC(ctx);
    
    http_events.perf_submit(ctx, &data, sizeof(data));
    http_start.delete(&pid_tgid);
    
    return 0;
}

// Trace file operations (open, read, write)
int trace_open_entry(struct pt_regs *ctx) {
    struct io_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Only trace MinIO processes
    if (data.comm[0] != 'm' || data.comm[1] != 'i' || data.comm[2] != 'n' || 
        data.comm[3] != 'i' || data.comm[4] != 'o') {
        return 0;
    }
    
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_str(&data.filename, sizeof(data.filename), filename);
    
    __builtin_memcpy(&data.op, "OPEN", 5);
    
    io_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_read_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Only trace MinIO processes
    if (comm[0] != 'm' || comm[1] != 'i' || comm[2] != 'n' || 
        comm[3] != 'i' || comm[4] != 'o') {
        return 0;
    }
    
    io_start.update(&pid_tgid, &ts);
    return 0;
}

int trace_read_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *tsp = io_start.lookup(&pid_tgid);
    
    if (tsp == 0) {
        return 0;
    }
    
    struct io_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = pid_tgid >> 32;
    data.latency_ns = data.ts - *tsp;
    data.size = PT_REGS_RC(ctx);
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.op, "READ", 5);
    
    io_events.perf_submit(ctx, &data, sizeof(data));
    io_start.delete(&pid_tgid);
    
    return 0;
}

int trace_write_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Only trace MinIO processes
    if (comm[0] != 'm' || comm[1] != 'i' || comm[2] != 'n' || 
        comm[3] != 'i' || comm[4] != 'o') {
        return 0;
    }
    
    io_start.update(&pid_tgid, &ts);
    return 0;
}

int trace_write_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *tsp = io_start.lookup(&pid_tgid);
    
    if (tsp == 0) {
        return 0;
    }
    
    struct io_data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = pid_tgid >> 32;
    data.latency_ns = data.ts - *tsp;
    data.size = PT_REGS_RC(ctx);
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.op, "WRITE", 6);
    
    io_events.perf_submit(ctx, &data, sizeof(data));
    io_start.delete(&pid_tgid);
    
    return 0;
}

// Trace S3 API operations using USDT probes (if MinIO is compiled with them)
// MinIO can be compiled with USDT probes for better observability
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Attach probes
# For MinIO binary (Go application), we trace syscalls
b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_open_entry")
b.attach_kprobe(event="__x64_sys_read", fn_name="trace_read_entry")
b.attach_kretprobe(event="__x64_sys_read", fn_name="trace_read_return")
b.attach_kprobe(event="__x64_sys_write", fn_name="trace_write_entry")
b.attach_kretprobe(event="__x64_sys_write", fn_name="trace_write_return")

# Try to attach to MinIO HTTP handlers (requires knowledge of Go binary symbols)
try:
    # Example: Attach to MinIO handler functions
    # You'd need to find actual function names using:
    # objdump -t /usr/local/bin/minio | grep -i handler
    b.attach_uprobe(
        name="/usr/local/bin/minio",
        sym="main.(*serverMain).Handle",
        fn_name="trace_http_handler_start",
    )
    b.attach_uretprobe(
        name="/usr/local/bin/minio",
        sym="main.(*serverMain).Handle",
        fn_name="trace_http_handler_end",
    )
except:
    print("Warning: Could not attach to MinIO HTTP handlers")


# Data structures
class HTTPData(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("method", ct.c_char * 8),
        ("path", ct.c_char * 128),
        ("latency_ns", ct.c_ulonglong),
        ("status_code", ct.c_int),
    ]


class IOData(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 64),
        ("offset", ct.c_ulonglong),
        ("size", ct.c_ulonglong),
        ("op", ct.c_char * 8),
        ("latency_ns", ct.c_ulonglong),
    ]


# Headers
print("MinIO eBPF Trace - Monitoring S3 operations and disk I/O")
print("=" * 80)


# Process HTTP events
def print_http_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(HTTPData)).contents
    latency_ms = event.latency_ns / 1000000.0

    print(
        "HTTP | %-9s | PID: %-6d | %-6s %-64s | Latency: %.2fms | Status: %d"
        % (
            strftime("%H:%M:%S"),
            event.pid,
            event.method.decode("utf-8", "replace"),
            event.path.decode("utf-8", "replace"),
            latency_ms,
            event.status_code,
        )
    )


# Process I/O events
def print_io_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(IOData)).contents
    latency_us = event.latency_ns / 1000.0 if event.latency_ns > 0 else 0

    print(
        "I/O  | %-9s | PID: %-6d | %-6s | File: %-32s | Size: %-8d | Latency: %.2fus"
        % (
            strftime("%H:%M:%S"),
            event.pid,
            event.op.decode("utf-8", "replace"),
            event.filename.decode("utf-8", "replace")[-32:],
            event.size,
            latency_us,
        )
    )


# Open perf buffers
b["http_events"].open_perf_buffer(print_http_event)
b["io_events"].open_perf_buffer(print_io_event)

print("\nTracing MinIO operations... Hit Ctrl-C to end.\n")

# Poll for events
while True:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\nDetaching probes...")
        exit()
