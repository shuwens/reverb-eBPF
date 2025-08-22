// Debug I/O Tracer - Traces ALL processes to debug detection
// File: debug_io_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16

struct debug_io_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u32 is_read; // 1 for read, 0 for write
  u64 size;
  s32 retval;
  char comm[MAX_COMM_LEN];
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Syscall read exit tracing - trace ALL processes
SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
  // Only trace successful reads with actual data
  if (ctx->ret <= 0)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  struct debug_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct debug_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->is_read = 1;
  event->size = ctx->ret;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// Syscall write exit tracing - trace ALL processes
SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
  // Only trace successful writes with actual data
  if (ctx->ret <= 0)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  struct debug_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct debug_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->is_read = 0;
  event->size = ctx->ret;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";
