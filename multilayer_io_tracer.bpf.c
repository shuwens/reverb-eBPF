// Multi-Layer I/O Tracer - Comprehensive storage stack tracing
// File: multilayer_io_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_ENTRIES 10240
#define MAX_FILENAME_LEN 256

// Layer definitions
#define LAYER_APPLICATION 1
#define LAYER_STORAGE_SERVICE 2
#define LAYER_OPERATING_SYSTEM 3
#define LAYER_FILESYSTEM 4
#define LAYER_DEVICE 5

// Event types per layer
// Application Layer
#define EVENT_APP_READ 101
#define EVENT_APP_WRITE 102
#define EVENT_APP_OPEN 103
#define EVENT_APP_CLOSE 104
#define EVENT_APP_FSYNC 105

// Storage Service Layer (userspace storage daemons)
#define EVENT_STORAGE_REPLICATION 201
#define EVENT_STORAGE_ERASURE_CODE 202
#define EVENT_STORAGE_METADATA_UPDATE 203
#define EVENT_STORAGE_CONSISTENCY_PROTOCOL 204

// Operating System Layer
#define EVENT_OS_SYSCALL_ENTER 301
#define EVENT_OS_SYSCALL_EXIT 302
#define EVENT_OS_VFS_READ 303
#define EVENT_OS_VFS_WRITE 304
#define EVENT_OS_PAGE_CACHE_HIT 305
#define EVENT_OS_PAGE_CACHE_MISS 306
#define EVENT_OS_CONTEXT_SWITCH 307

// Filesystem Layer
#define EVENT_FS_JOURNAL_WRITE 401
#define EVENT_FS_METADATA_UPDATE 402
#define EVENT_FS_DATA_WRITE 403
#define EVENT_FS_INODE_UPDATE 404
#define EVENT_FS_EXTENT_ALLOC 405
#define EVENT_FS_BLOCK_ALLOC 406

// Device Layer
#define EVENT_DEV_BIO_SUBMIT 501
#define EVENT_DEV_BIO_COMPLETE 502
#define EVENT_DEV_REQUEST_QUEUE 503
#define EVENT_DEV_REQUEST_COMPLETE 504
#define EVENT_DEV_FTL_WRITE 505
#define EVENT_DEV_TRIM 506

// Storage system types
#define SYSTEM_TYPE_UNKNOWN 0
#define SYSTEM_TYPE_MINIO 1
#define SYSTEM_TYPE_CEPH 2
#define SYSTEM_TYPE_ETCD 3
#define SYSTEM_TYPE_POSTGRES 4
#define SYSTEM_TYPE_GLUSTER 5
#define SYSTEM_TYPE_APPLICATION 6

struct io_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u8 layer;
  u32 event_type;
  u32 system_type;
  u64 size;
  u64 offset;
  u64 latency_ns;
  u32 dev_major;
  u32 dev_minor;
  s32 retval;
  u64 inode;
  u64 request_id; // For correlating events
  char comm[MAX_COMM_LEN];
  char filename[MAX_FILENAME_LEN];

  // Additional metrics
  u64 aligned_size;      // After alignment/padding
  u32 replication_count; // For storage service layer
  u32 block_count;       // Number of blocks affected
  u8 is_metadata;        // Flag for metadata operations
  u8 is_journal;         // Flag for journal operations
  u8 cache_hit;          // For page cache tracking
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024); // Larger buffer for more events
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, u64);
} io_start_times SEC(".maps");

// Track request flow through layers
struct request_context {
  u64 app_request_id;
  u64 original_size;
  u64 timestamp;
  u32 system_type;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64); // pid_tgid
  __type(value, struct request_context);
} request_tracking SEC(".maps");

// Helper to detect storage system type
static __always_inline u32 detect_system_type(const char *comm) {
  // Check for storage system process names
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'm' && comm[i + 1] == 'i' && comm[i + 2] == 'n' &&
        comm[i + 3] == 'i')
      return SYSTEM_TYPE_MINIO;
    if (comm[i] == 'c' && comm[i + 1] == 'e' && comm[i + 2] == 'p' &&
        comm[i + 3] == 'h')
      return SYSTEM_TYPE_CEPH;
    if (comm[i] == 'e' && comm[i + 1] == 't' && comm[i + 2] == 'c' &&
        comm[i + 3] == 'd')
      return SYSTEM_TYPE_ETCD;
    if (comm[i] == 'p' && comm[i + 1] == 'o' && comm[i + 2] == 's' &&
        comm[i + 3] == 't')
      return SYSTEM_TYPE_POSTGRES;
    if (comm[i] == 'g' && comm[i + 1] == 'l' && comm[i + 2] == 'u' &&
        comm[i + 3] == 's')
      return SYSTEM_TYPE_GLUSTER;
  }

  // Check if it's a regular application
  if (comm[0] != '\0' && comm[0] != ' ')
    return SYSTEM_TYPE_APPLICATION;

  return SYSTEM_TYPE_UNKNOWN;
}

// Generate unique request ID
static __always_inline u64 generate_request_id(u64 pid_tgid) {
  u64 ts = bpf_ktime_get_ns();
  return (pid_tgid << 32) | (ts & 0xFFFFFFFF);
}

// ============================================================================
// LAYER 1: APPLICATION LAYER TRACING
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_write")
int trace_app_write_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  // Create request context for tracking through layers
  struct request_context req_ctx = {};
  req_ctx.app_request_id = generate_request_id(pid_tgid);
  req_ctx.original_size = ctx->args[2]; // count parameter
  req_ctx.timestamp = bpf_ktime_get_ns();
  req_ctx.system_type = detect_system_type(comm);

  bpf_map_update_elem(&request_tracking, &pid_tgid, &req_ctx, BPF_ANY);
  bpf_map_update_elem(&io_start_times, &pid_tgid, &req_ctx.timestamp, BPF_ANY);

  // Record application layer event
  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = req_ctx.timestamp;
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_APPLICATION;
  event->event_type = EVENT_APP_WRITE;
  event->system_type = req_ctx.system_type;
  event->size = req_ctx.original_size;
  event->request_id = req_ctx.app_request_id;
  event->offset = 0;
  event->latency_ns = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_app_read_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  struct request_context req_ctx = {};
  req_ctx.app_request_id = generate_request_id(pid_tgid);
  req_ctx.original_size = ctx->args[2]; // count parameter
  req_ctx.timestamp = bpf_ktime_get_ns();
  req_ctx.system_type = detect_system_type(comm);

  bpf_map_update_elem(&request_tracking, &pid_tgid, &req_ctx, BPF_ANY);
  bpf_map_update_elem(&io_start_times, &pid_tgid, &req_ctx.timestamp, BPF_ANY);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = req_ctx.timestamp;
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_APPLICATION;
  event->event_type = EVENT_APP_READ;
  event->system_type = req_ctx.system_type;
  event->size = req_ctx.original_size;
  event->request_id = req_ctx.app_request_id;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// LAYER 2: STORAGE SERVICE LAYER (Userspace storage daemons)
// ============================================================================

// Trace storage service operations via their specific syscalls patterns
SEC("kprobe/sys_sendmsg")
int trace_storage_replication(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  u32 system_type = detect_system_type(comm);
  if (system_type == SYSTEM_TYPE_UNKNOWN ||
      system_type == SYSTEM_TYPE_APPLICATION)
    return 0;

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);
  if (!req_ctx)
    return 0;

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_STORAGE_SERVICE;
  event->event_type = EVENT_STORAGE_REPLICATION;
  event->system_type = system_type;
  event->request_id = req_ctx->app_request_id;
  event->size = req_ctx->original_size;
  event->replication_count = 3; // Typical replication factor
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// LAYER 3: OPERATING SYSTEM LAYER
// ============================================================================

SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  size_t count = PT_REGS_PARM3(ctx);

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_OPERATING_SYSTEM;
  event->event_type = EVENT_OS_VFS_READ;
  event->size = count;

  // Try to get inode
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  if (inode) {
    event->inode = BPF_CORE_READ(inode, i_ino);
  }

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->system_type = req_ctx->system_type;
  }

  // Check if size was aligned to page boundary
  event->aligned_size = (count + 4095) & ~4095; // Round up to 4KB

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  size_t count = PT_REGS_PARM3(ctx);

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_OPERATING_SYSTEM;
  event->event_type = EVENT_OS_VFS_WRITE;
  event->size = count;

  struct inode *inode = BPF_CORE_READ(file, f_inode);
  if (inode) {
    event->inode = BPF_CORE_READ(inode, i_ino);
  }

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->system_type = req_ctx->system_type;
  }

  event->aligned_size = (count + 4095) & ~4095;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// Page cache operations
SEC("kprobe/pagecache_get_page")
int trace_page_cache_access(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_OPERATING_SYSTEM;
  event->event_type = EVENT_OS_PAGE_CACHE_MISS; // Will be updated if hit
  event->size = 4096;                           // Page size

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// LAYER 4: FILESYSTEM LAYER
// ============================================================================

// EXT4 specific tracing
SEC("kprobe/ext4_journal_start")
int trace_ext4_journal_start(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int nblocks = PT_REGS_PARM2(ctx);

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_FILESYSTEM;
  event->event_type = EVENT_FS_JOURNAL_WRITE;
  event->block_count = nblocks;
  event->size = nblocks * 4096;
  event->is_journal = 1;

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->system_type = req_ctx->system_type;
  }

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// XFS tracing
SEC("kprobe/xfs_trans_alloc")
int trace_xfs_transaction(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_FILESYSTEM;
  event->event_type = EVENT_FS_JOURNAL_WRITE;
  event->is_journal = 1;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// Generic filesystem metadata operations
SEC("kprobe/mark_inode_dirty")
int trace_inode_dirty(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_FILESYSTEM;
  event->event_type = EVENT_FS_INODE_UPDATE;
  event->is_metadata = 1;

  if (inode) {
    event->inode = BPF_CORE_READ(inode, i_ino);
  }

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// LAYER 5: DEVICE LAYER
// ============================================================================

SEC("kprobe/submit_bio")
int trace_bio_submit(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_DEVICE;
  event->event_type = EVENT_DEV_BIO_SUBMIT;

  // Safely read bio fields
  unsigned int bi_size = BPF_CORE_READ(bio, bi_iter.bi_size);
  unsigned int bi_opf = BPF_CORE_READ(bio, bi_opf);
  sector_t bi_sector = BPF_CORE_READ(bio, bi_iter.bi_sector);

  event->size = bi_size;
  event->offset = bi_sector * 512; // Convert sectors to bytes

  // Get device info
  struct block_device *bdev = BPF_CORE_READ(bio, bi_bdev);
  if (bdev) {
    dev_t dev = BPF_CORE_READ(bdev, bd_dev);
    event->dev_major = dev >> 20;
    event->dev_minor = dev & 0xFFFFF;
  }

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->system_type = req_ctx->system_type;
  }

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);

  // Track bio for completion
  u64 bio_addr = (u64)bio;
  u64 start_time = bpf_ktime_get_ns();
  bpf_map_update_elem(&io_start_times, &bio_addr, &start_time, BPF_ANY);

  return 0;
}

SEC("kprobe/bio_endio")
int trace_bio_complete(struct pt_regs *ctx) {
  struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
  u64 bio_addr = (u64)bio;

  u64 *start_time = bpf_map_lookup_elem(&io_start_times, &bio_addr);
  if (!start_time)
    return 0;

  u64 latency = bpf_ktime_get_ns() - *start_time;

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&io_start_times, &bio_addr);
    return 0;
  }

  event->timestamp = bpf_ktime_get_ns();
  event->layer = LAYER_DEVICE;
  event->event_type = EVENT_DEV_BIO_COMPLETE;
  event->latency_ns = latency;

  unsigned int bi_size = BPF_CORE_READ(bio, bi_iter.bi_size);
  event->size = bi_size;

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&io_start_times, &bio_addr);

  return 0;
}

// TRIM/Discard operations
SEC("kprobe/blkdev_issue_discard")
int trace_trim(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  sector_t sector = PT_REGS_PARM2(ctx);
  sector_t nr_sects = PT_REGS_PARM3(ctx);

  struct io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid_tgid >> 32;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_DEVICE;
  event->event_type = EVENT_DEV_TRIM;
  event->offset = sector * 512;
  event->size = nr_sects * 512;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
