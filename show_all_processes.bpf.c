// Show All Processes Tracer - Debug what process names we're actually seeing
// File: show_all_processes.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16

struct process_event {
  u64 timestamp;
  u32 pid;
  u64 size;
  s32 retval;
  char comm[MAX_COMM_LEN];
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Trace ALL write syscalls - no filtering
SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
  // Only trace writes that actually wrote data
  if (ctx->ret <= 0)
    return 0;

  // Skip very small writes (< 10 bytes) to reduce noise
  if (ctx->ret < 10)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  struct process_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->size = ctx->ret;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";
