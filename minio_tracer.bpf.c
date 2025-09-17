// MinIO-specific Multi-Layer I/O Tracer with Request Correlation
// File: minio_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_ENTRIES 10240
#define MAX_FILENAME_LEN 256
#define MAX_REQUEST_BRANCHES 8

// Layer definitions
#define LAYER_APPLICATION 1
#define LAYER_STORAGE_SERVICE 2
#define LAYER_OPERATING_SYSTEM 3
#define LAYER_FILESYSTEM 4
#define LAYER_DEVICE 5

// MinIO-specific event types
#define EVENT_MINIO_OBJECT_PUT 110
#define EVENT_MINIO_OBJECT_GET 111
#define EVENT_MINIO_ERASURE_ENCODE 112
#define EVENT_MINIO_ERASURE_DECODE 113
#define EVENT_MINIO_XL_META 114
#define EVENT_MINIO_REPLICATION 115

// Standard event types
#define EVENT_OS_VFS_READ 303
#define EVENT_OS_VFS_WRITE 304
#define EVENT_FS_SYNC 401
#define EVENT_DEV_BIO_SUBMIT 501
#define EVENT_DEV_BIO_COMPLETE 502

struct multilayer_io_event {
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
  u64 request_id;
  u64 parent_request_id; // For tracking request hierarchy
  u32 branch_id;         // For tracking parallel operations
  u32 branch_count;      // Total branches for this request
  char comm[MAX_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  u64 aligned_size;
  u32 replication_count;
  u32 block_count;
  u8 is_metadata;
  u8 is_journal;
  u8 cache_hit;
  u8 is_erasure;
  u8 erasure_data_blocks;
  u8 erasure_parity_blocks;
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, u64);
} io_start_times SEC(".maps");

// Enhanced request context for MinIO
struct request_context {
  u64 app_request_id;
  u64 parent_request_id;
  u64 original_size;
  u64 timestamp;
  u32 system_type;
  u32 branch_count;
  u8 is_minio_op;
  u8 op_type; // 0=GET, 1=PUT
  char object_name[64];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, struct request_context);
} request_tracking SEC(".maps");

// Track request branching and merging
struct request_branch {
  u64 parent_request_id;
  u32 branch_id;
  u32 total_branches;
  u64 branch_timestamp;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES * 4);
  __type(key, u64);
  __type(value, struct request_branch);
} request_branches SEC(".maps");

// Helper to check if process is MinIO (but not the tracer itself)
static __always_inline bool is_minio_process(const char *comm) {
  // Exclude the tracer itself to prevent infinite loops
  if (comm[0] == 'm' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'i' &&
      comm[4] == 'o' && comm[5] == '_' && comm[6] == 't' && comm[7] == 'r' &&
      comm[8] == 'a' && comm[9] == 'c' && comm[10] == 'e' && comm[11] == 'r') {
    return false; // This is minio_tracer, not MinIO server
  }

  // Check if comm is exactly "minio" or starts with "minio "
  if (comm[0] == 'm' && comm[1] == 'i' && comm[2] == 'n' && comm[3] == 'i' &&
      comm[4] == 'o') {
    // Check if it's exactly "minio" or "minio " followed by args
    if (comm[5] == '\0' || comm[5] == ' ') {
      return true;
    }
  }

  return false;
}

// Helper to check if filename is MinIO-related
static __always_inline bool is_minio_file(const char *filename) {
  if (!filename)
    return false;

  // Check for xl.meta files (MinIO metadata)
  for (int i = 0; i < MAX_FILENAME_LEN - 7; i++) {
    if (filename[i] == 'x' && filename[i + 1] == 'l' &&
        filename[i + 2] == '.' && filename[i + 3] == 'm' &&
        filename[i + 4] == 'e' && filename[i + 5] == 't' &&
        filename[i + 6] == 'a')
      return true;
  }

  // Check for part files (erasure coded data)
  for (int i = 0; i < MAX_FILENAME_LEN - 4; i++) {
    if (filename[i] == 'p' && filename[i + 1] == 'a' &&
        filename[i + 2] == 'r' && filename[i + 3] == 't')
      return true;
  }

  return false;
}

static __always_inline u64 generate_request_id(u64 pid_tgid) {
  u64 ts = bpf_ktime_get_ns();
  return (pid_tgid << 32) | (ts & 0xFFFFFFFF);
}

static __always_inline void init_event(struct multilayer_io_event *event) {
  __builtin_memset(event, 0, sizeof(struct multilayer_io_event));
}

// ============================================================================
// MinIO Application Layer Tracing - Hook into MinIO operations
// ============================================================================

// Trace MinIO PUT operations via write syscalls with correlation
SEC("tracepoint/syscalls/sys_enter_write")
int trace_minio_write(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Only trace MinIO processes
  if (!is_minio_process(comm))
    return 0;

  // Create or update request context
  struct request_context req_ctx = {};
  struct request_context *existing =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  if (existing && existing->parent_request_id != 0) {
    // This is a branched request
    req_ctx = *existing;
    req_ctx.branch_count++;
  } else {
    // New request
    req_ctx.app_request_id = generate_request_id(pid_tgid);
    req_ctx.parent_request_id = 0;
    req_ctx.original_size = ctx->args[2];
    req_ctx.timestamp = bpf_ktime_get_ns();
    req_ctx.system_type = 1; // MINIO
    req_ctx.is_minio_op = 1;
    req_ctx.op_type = 1; // PUT
    req_ctx.branch_count = 0;
  }

  bpf_map_update_elem(&request_tracking, &pid_tgid, &req_ctx, BPF_ANY);
  bpf_map_update_elem(&io_start_times, &pid_tgid, &req_ctx.timestamp, BPF_ANY);

  // Generate event
  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = req_ctx.timestamp;
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_APPLICATION;
  event->event_type = EVENT_MINIO_OBJECT_PUT;
  event->system_type = 1; // MINIO
  event->size = ctx->args[2];
  event->request_id = req_ctx.app_request_id;
  event->parent_request_id = req_ctx.parent_request_id;
  event->branch_id = req_ctx.branch_count;
  event->aligned_size = ctx->args[2];

  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// Trace MinIO GET operations via read syscalls
SEC("tracepoint/syscalls/sys_enter_read")
int trace_minio_read(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Only trace MinIO processes
  if (!is_minio_process(comm))
    return 0;

  struct request_context req_ctx = {};
  struct request_context *existing =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  if (existing && existing->parent_request_id != 0) {
    req_ctx = *existing;
    req_ctx.branch_count++;
  } else {
    req_ctx.app_request_id = generate_request_id(pid_tgid);
    req_ctx.parent_request_id = 0;
    req_ctx.original_size = ctx->args[2];
    req_ctx.timestamp = bpf_ktime_get_ns();
    req_ctx.system_type = 1; // MINIO
    req_ctx.is_minio_op = 1;
    req_ctx.op_type = 0; // GET
    req_ctx.branch_count = 0;
  }

  bpf_map_update_elem(&request_tracking, &pid_tgid, &req_ctx, BPF_ANY);
  bpf_map_update_elem(&io_start_times, &pid_tgid, &req_ctx.timestamp, BPF_ANY);

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = req_ctx.timestamp;
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_APPLICATION;
  event->event_type = EVENT_MINIO_OBJECT_GET;
  event->system_type = 1; // MINIO
  event->size = ctx->args[2];
  event->request_id = req_ctx.app_request_id;
  event->parent_request_id = req_ctx.parent_request_id;
  event->branch_id = req_ctx.branch_count;
  event->aligned_size = ctx->args[2];

  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// MinIO Storage Service Layer - Track erasure coding and metadata
// ============================================================================

SEC("kprobe/vfs_open")
int trace_minio_metadata(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_minio_process(comm))
    return 0;

  struct path *path = (struct path *)PT_REGS_PARM1(ctx);
  if (!path)
    return 0;

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);
  if (!req_ctx)
    return 0;

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_STORAGE_SERVICE;
  event->event_type = EVENT_MINIO_XL_META;
  event->system_type = 1; // MINIO
  event->size = 0;        // Metadata operation
  event->request_id = req_ctx->app_request_id;
  event->parent_request_id = req_ctx->parent_request_id;
  event->is_metadata = 1;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);

  return 0;
}

// ============================================================================
// OS Layer - VFS operations with request correlation
// ============================================================================

SEC("kprobe/vfs_read")
int trace_vfs_read_correlated(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Only trace MinIO processes
  if (!is_minio_process(comm))
    return 0;

  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  size_t count = PT_REGS_PARM3(ctx);

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);
  if (!req_ctx)
    return 0;

  // Check for branching - multiple reads for same request
  struct request_branch branch = {};
  u64 branch_key = pid_tgid ^ bpf_ktime_get_ns();

  struct request_branch *existing_branch =
      bpf_map_lookup_elem(&request_branches, &branch_key);
  if (!existing_branch) {
    branch.parent_request_id = req_ctx->app_request_id;
    branch.branch_id = req_ctx->branch_count++;
    branch.total_branches = 1;
    branch.branch_timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&request_branches, &branch_key, &branch, BPF_ANY);
  }

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_OPERATING_SYSTEM;
  event->event_type = EVENT_OS_VFS_READ;
  event->size = count;
  event->request_id = req_ctx->app_request_id;
  event->parent_request_id = req_ctx->parent_request_id;
  event->branch_id = branch.branch_id;
  event->branch_count = req_ctx->branch_count;

  // Try to get inode
  if (file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
      event->inode = BPF_CORE_READ(inode, i_ino);
    }
  }

  event->aligned_size = (count + 4095) & ~4095ULL;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/vfs_write")
int trace_vfs_write_correlated(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_minio_process(comm))
    return 0;

  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  size_t count = PT_REGS_PARM3(ctx);

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);
  if (!req_ctx)
    return 0;

  // Track branching for parallel writes
  struct request_branch branch = {};
  u64 branch_key = pid_tgid ^ bpf_ktime_get_ns();

  branch.parent_request_id = req_ctx->app_request_id;
  branch.branch_id = req_ctx->branch_count++;
  branch.total_branches = 1;
  branch.branch_timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&request_branches, &branch_key, &branch, BPF_ANY);

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_OPERATING_SYSTEM;
  event->event_type = EVENT_OS_VFS_WRITE;
  event->size = count;
  event->request_id = req_ctx->app_request_id;
  event->parent_request_id = req_ctx->parent_request_id;
  event->branch_id = branch.branch_id;
  event->branch_count = req_ctx->branch_count;

  if (file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
      event->inode = BPF_CORE_READ(inode, i_ino);
    }
  }

  event->aligned_size = (count + 4095) & ~4095ULL;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// Filesystem Layer - Track sync operations with correlation
// ============================================================================

SEC("kprobe/vfs_fsync_range")
int trace_fs_sync_correlated(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_minio_process(comm))
    return 0;

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_FILESYSTEM;
  event->event_type = EVENT_FS_SYNC;
  event->size = 0;
  event->aligned_size = 0;
  event->is_metadata = 1;

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->parent_request_id = req_ctx->parent_request_id;
    event->branch_id = req_ctx->branch_count;
  }

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// Device Layer - Block I/O with correlation
// ============================================================================

SEC("kprobe/submit_bio")
int trace_bio_submit_correlated(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_minio_process(comm))
    return 0;

  struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
  if (!bio)
    return 0;

  struct request_context *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_DEVICE;
  event->event_type = EVENT_DEV_BIO_SUBMIT;

  unsigned int bi_size = BPF_CORE_READ(bio, bi_iter.bi_size);
  sector_t bi_sector = BPF_CORE_READ(bio, bi_iter.bi_sector);

  event->size = bi_size;
  event->aligned_size = bi_size;
  event->offset = bi_sector * 512;

  // Determine if this is journal I/O (typically small, sequential writes)
  if (bi_size <= 8192) {
    event->is_journal = 1;
  }

  struct block_device *bdev = BPF_CORE_READ(bio, bi_bdev);
  if (bdev) {
    dev_t dev = BPF_CORE_READ(bdev, bd_dev);
    event->dev_major = dev >> 20;
    event->dev_minor = dev & 0xFFFFF;
  }

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->parent_request_id = req_ctx->parent_request_id;
    event->branch_id = req_ctx->branch_count;
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
int trace_bio_complete_correlated(struct pt_regs *ctx) {
  struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
  if (!bio)
    return 0;

  u64 bio_addr = (u64)bio;

  u64 *start_time = bpf_map_lookup_elem(&io_start_times, &bio_addr);
  if (!start_time)
    return 0;

  u64 latency = bpf_ktime_get_ns() - *start_time;

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&io_start_times, &bio_addr);
    return 0;
  }

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->layer = LAYER_DEVICE;
  event->event_type = EVENT_DEV_BIO_COMPLETE;
  event->latency_ns = latency;

  unsigned int bi_size = BPF_CORE_READ(bio, bi_iter.bi_size);
  event->size = bi_size;
  event->aligned_size = bi_size;

  if (bi_size <= 8192) {
    event->is_journal = 1;
  }

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&io_start_times, &bio_addr);

  return 0;
}

char _license[] SEC("license") = "GPL";
