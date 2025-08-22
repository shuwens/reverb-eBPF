#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_ENTRIES 10240

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_BLOCK_READ 3
#define EVENT_TYPE_BLOCK_WRITE 4
#define EVENT_TYPE_VFS_READ 5
#define EVENT_TYPE_VFS_WRITE 6

// Storage system types
#define SYSTEM_TYPE_UNKNOWN 0
#define SYSTEM_TYPE_MINIO 1
#define SYSTEM_TYPE_CEPH 2
#define SYSTEM_TYPE_ETCD 3
#define SYSTEM_TYPE_POSTGRES 4
#define SYSTEM_TYPE_GLUSTER 5

struct io_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 event_type;
  __u32 system_type;
  __u64 offset;
  __u64 size;
  __u64 latency_start;
  __u32 dev_major;
  __u32 dev_minor;
  __u32 retval;
  char comm[MAX_COMM_LEN];
  char filename[MAX_PATH_LEN];
};

// Maps for storing events and state
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u64);
  __type(value, __u64);
} start_times SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u32);
} pid_to_system SEC(".maps");

// Helper function to detect storage system type based on process name
static __always_inline __u32 detect_system_type(const char *comm) {
  if (bpf_strstr(comm, "minio") != NULL)
    return SYSTEM_TYPE_MINIO;
  if (bpf_strstr(comm, "ceph") != NULL)
    return SYSTEM_TYPE_CEPH;
  if (bpf_strstr(comm, "etcd") != NULL)
    return SYSTEM_TYPE_ETCD;
  if (bpf_strstr(comm, "postgres") != NULL)
    return SYSTEM_TYPE_POSTGRES;
  if (bpf_strstr(comm, "gluster") != NULL)
    return SYSTEM_TYPE_GLUSTER;
  return SYSTEM_TYPE_UNKNOWN;
}

// VFS layer tracing - entry point
SEC("kprobe/vfs_read")
int trace_vfs_read_entry(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u64 timestamp = bpf_ktime_get_ns();

  // Store start time for latency calculation
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("kretprobe/vfs_read")
int trace_vfs_read_exit(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  __u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  __u64 timestamp = bpf_ktime_get_ns();
  __u64 latency = timestamp - *start_time;

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_READ;
  event->system_type = system_type;
  event->size = PT_REGS_RC(ctx); // Return value is bytes read
  event->latency_start = latency;
  event->retval = PT_REGS_RC(ctx);
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

SEC("kprobe/vfs_write")
int trace_vfs_write_entry(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 timestamp = bpf_ktime_get_ns();

  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("kretprobe/vfs_write")
int trace_vfs_write_exit(struct pt_regs *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  __u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  __u64 timestamp = bpf_ktime_get_ns();
  __u64 latency = timestamp - *start_time;

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_WRITE;
  event->system_type = system_type;
  event->size = PT_REGS_RC(ctx);
  event->latency_start = latency;
  event->retval = PT_REGS_RC(ctx);
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// Block layer tracing
SEC("kprobe/blk_account_io_start")
int trace_block_io_start(struct pt_regs *ctx) {
  struct request *rq = (struct request *)PT_REGS_PARM1(ctx);

  __u64 timestamp = bpf_ktime_get_ns();
  __u64 key = (__u64)rq;

  bpf_map_update_elem(&start_times, &key, &timestamp, BPF_ANY);

  return 0;
}

SEC("kprobe/blk_account_io_done")
int trace_block_io_done(struct pt_regs *ctx) {
  struct request *rq = (struct request *)PT_REGS_PARM1(ctx);

  __u64 key = (__u64)rq;
  __u64 *start_time = bpf_map_lookup_elem(&start_times, &key);
  if (!start_time)
    return 0;

  __u64 timestamp = bpf_ktime_get_ns();
  __u64 latency = timestamp - *start_time;

  // Get process info from current context
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN) {
    bpf_map_delete_elem(&start_times, &key);
    return 0;
  }

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &key);
    return 0;
  }

  // Read request details
  __u32 cmd_flags;
  __u64 sector, nr_sectors;

  bpf_probe_read_kernel(&cmd_flags, sizeof(cmd_flags), &rq->cmd_flags);
  bpf_probe_read_kernel(&sector, sizeof(sector), &rq->__sector);
  bpf_probe_read_kernel(&nr_sectors, sizeof(nr_sectors), &rq->__data_len);

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->system_type = system_type;
  event->offset = sector * 512; // Convert to bytes
  event->size = nr_sectors;
  event->latency_start = latency;

  // Determine if read or write
  if (cmd_flags & REQ_OP_WRITE) {
    event->event_type = EVENT_TYPE_BLOCK_WRITE;
  } else {
    event->event_type = EVENT_TYPE_BLOCK_READ;
  }

  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &key);

  return 0;
}

// Syscall tracing for high-level operations
SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  __u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  __u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  __u64 timestamp = bpf_ktime_get_ns();
  __u64 latency = timestamp - *start_time;

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
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

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  __u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  __u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN)
    return 0;

  __u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  __u64 timestamp = bpf_ktime_get_ns();
  __u64 latency = timestamp - *start_time;

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
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
