// Simple I/O Tracer - Minimal version for initial testing
// File: simple_io_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_ENTRIES 10240

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2

// Storage system types
#define SYSTEM_TYPE_UNKNOWN 0
#define SYSTEM_TYPE_MINIO 1
#define SYSTEM_TYPE_CEPH 2
#define SYSTEM_TYPE_ETCD 3
#define SYSTEM_TYPE_POSTGRES 4
#define SYSTEM_TYPE_GLUSTER 5

struct storage_io_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u32 event_type;
  u32 system_type;
  u64 size;
  u64 latency_start;
  s32 retval;
  char comm[MAX_COMM_LEN];
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, u64);
} start_times SEC(".maps");

// Helper function to detect storage system type
static __always_inline u32 detect_system_type(const char *comm) {
  // Simple string matching for common storage systems
  char c1 = comm[0];
  char c2 = comm[1];
  char c3 = comm[2];
  char c4 = comm[3];

  // Check for "minio"
  if (c1 == 'm' && c2 == 'i' && c3 == 'n' && c4 == 'i')
    return SYSTEM_TYPE_MINIO;

  // Check for "ceph"
  if (c1 == 'c' && c2 == 'e' && c3 == 'p' && c4 == 'h')
    return SYSTEM_TYPE_CEPH;

  // Check for "etcd"
  if (c1 == 'e' && c2 == 't' && c3 == 'c' && c4 == 'd')
    return SYSTEM_TYPE_ETCD;

  // Check for "postgres"
  if (c1 == 'p' && c2 == 'o' && c3 == 's' && c4 == 't')
    return SYSTEM_TYPE_POSTGRES;

  // Check for "gluster"
  if (c1 == 'g' && c2 == 'l' && c3 == 'u' && c4 == 's')
    return SYSTEM_TYPE_GLUSTER;

  return SYSTEM_TYPE_UNKNOWN;
}

// Syscall read tracing
SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  u64 timestamp = bpf_ktime_get_ns();
  u64 latency = timestamp - *start_time;

  struct storage_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct storage_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_READ;
  event->system_type = system_type;
  event->size = ctx->ret;
  event->latency_start = latency;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// Syscall write tracing
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  u64 timestamp = bpf_ktime_get_ns();
  u64 latency = timestamp - *start_time;

  struct storage_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct storage_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_WRITE;
  event->system_type = system_type;
  event->size = ctx->ret;
  event->latency_start = latency;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

char _license[] SEC("license") = "GPL";
