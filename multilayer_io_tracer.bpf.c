// Enhanced Multi-Layer I/O Tracer with MinIO-specific tracking - Fixed Stack
// Size File: multilayer_io_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_ENTRIES 10240
#define MAX_FILENAME_LEN 256
#define MAX_BUCKET_NAME_LEN 64

// Layer definitions
#define LAYER_APPLICATION 1
#define LAYER_STORAGE_SERVICE 2
#define LAYER_OPERATING_SYSTEM 3
#define LAYER_FILESYSTEM 4
#define LAYER_DEVICE 5

// Event types per layer
#define EVENT_APP_READ 101
#define EVENT_APP_WRITE 102
#define EVENT_OS_VFS_READ 303
#define EVENT_OS_VFS_WRITE 304
#define EVENT_FS_SYNC 401
#define EVENT_DEV_BIO_SUBMIT 501
#define EVENT_DEV_BIO_COMPLETE 502

// MinIO-specific event types
#define EVENT_MINIO_OBJECT_PUT 201
#define EVENT_MINIO_OBJECT_GET 202
#define EVENT_MINIO_ERASURE_WRITE 203
#define EVENT_MINIO_METADATA_UPDATE 204
#define EVENT_MINIO_BITROT_CHECK 205
#define EVENT_MINIO_MULTIPART 206
#define EVENT_MINIO_XL_META 207

// Storage system types
#define SYSTEM_TYPE_UNKNOWN 0
#define SYSTEM_TYPE_MINIO 1
#define SYSTEM_TYPE_CEPH 2
#define SYSTEM_TYPE_ETCD 3
#define SYSTEM_TYPE_POSTGRES 4
#define SYSTEM_TYPE_GLUSTER 5
#define SYSTEM_TYPE_APPLICATION 6

// MinIO tracking modes
#define MINIO_TRACE_OFF 0
#define MINIO_TRACE_NAME 1
#define MINIO_TRACE_PID 2
#define MINIO_TRACE_ALL 3

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
  char comm[MAX_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  u64 aligned_size;
  u32 replication_count;
  u32 block_count;
  u8 is_metadata;
  u8 is_journal;
  u8 cache_hit;

  // MinIO-specific fields
  u32 erasure_set_index;
  u32 erasure_block_index;
  u8 is_parity_block;
  u8 is_xl_meta;
  u32 object_part_number;
  char bucket_name[MAX_BUCKET_NAME_LEN];
  u8 is_minio;
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

// MinIO PID tracking map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u32);
  __type(value, u8);
} minio_pids SEC(".maps");

// MinIO configuration map
struct minio_config {
  u8 trace_mode;
  u8 trace_erasure;
  u8 trace_metadata;
  u8 verbose;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct minio_config);
} minio_config_map SEC(".maps");

// Simplified request context without large arrays
struct request_context_small {
  u64 app_request_id;
  u64 original_size;
  u64 timestamp;
  u32 system_type;
  u8 is_minio;
  u32 erasure_blocks;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, struct request_context_small);
} request_tracking SEC(".maps");

// Per-CPU array for temporary large structures
struct temp_storage {
  char filename[MAX_FILENAME_LEN];
  char object_name[MAX_FILENAME_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct temp_storage);
} temp_storage_map SEC(".maps");

// Helper to check if process is MinIO
static __always_inline bool is_minio_process(const char *comm, u32 pid) {
  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);
  if (!config)
    return false;

  if (config->trace_mode == MINIO_TRACE_OFF)
    return false;

  if (config->trace_mode == MINIO_TRACE_ALL)
    return true;

  // Check by PID
  if (config->trace_mode == MINIO_TRACE_PID) {
    u8 *val = bpf_map_lookup_elem(&minio_pids, &pid);
    return val != NULL;
  }

  // Check by name
  if (config->trace_mode == MINIO_TRACE_NAME) {
#pragma unroll
    for (int i = 0; i < 11; i++) { // MAX_COMM_LEN - 5
      if (i + 4 < MAX_COMM_LEN) {
        if (comm[i] == 'm' && comm[i + 1] == 'i' && comm[i + 2] == 'n' &&
            comm[i + 3] == 'i' && comm[i + 4] == 'o')
          return true;
      }
    }
  }

  return false;
}

// Helper to detect storage system type
static __always_inline u32 detect_system_type(const char *comm) {
#pragma unroll
  for (int i = 0; i < 12; i++) { // MAX_COMM_LEN - 4
    if (i + 4 < MAX_COMM_LEN) {
      if (comm[i] == 'm' && comm[i + 1] == 'i' && comm[i + 2] == 'n' &&
          comm[i + 3] == 'i' && comm[i + 4] == 'o')
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
  }

  if (comm[0] != '\0' && comm[0] != ' ')
    return SYSTEM_TYPE_APPLICATION;

  return SYSTEM_TYPE_UNKNOWN;
}

static __always_inline u64 generate_request_id(u64 pid_tgid) {
  u64 ts = bpf_ktime_get_ns();
  return (pid_tgid << 32) | (ts & 0xFFFFFFFF);
}

// Helper to initialize event structure with zeros
static __always_inline void init_event(struct multilayer_io_event *event) {
  __builtin_memset(event, 0, sizeof(struct multilayer_io_event));
}

// ============================================================================
// LAYER 1: APPLICATION LAYER - Using tracepoints
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_write")
int trace_app_write_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Check if we should trace this process
  bool trace_this = is_minio_process(comm, pid);

  // Get MinIO config
  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);

  // If MinIO-only mode and not MinIO, skip
  if (config && config->trace_mode != MINIO_TRACE_OFF && !trace_this)
    return 0;

  // Use smaller structure for stack
  struct request_context_small req_ctx = {};
  req_ctx.app_request_id = generate_request_id(pid_tgid);
  req_ctx.original_size = ctx->args[2];
  req_ctx.timestamp = bpf_ktime_get_ns();
  req_ctx.system_type = detect_system_type(comm);
  req_ctx.is_minio = trace_this;

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
  event->event_type = trace_this ? EVENT_MINIO_OBJECT_PUT : EVENT_APP_WRITE;
  event->system_type = req_ctx.system_type;
  event->size = req_ctx.original_size;
  event->request_id = req_ctx.app_request_id;
  event->aligned_size = req_ctx.original_size;
  event->latency_ns = 0;
  event->offset = 0;
  event->is_metadata = 0;
  event->is_journal = 0;
  event->cache_hit = 0;
  event->is_minio = trace_this;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_app_read_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  bool trace_this = is_minio_process(comm, pid);

  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);

  if (config && config->trace_mode != MINIO_TRACE_OFF && !trace_this)
    return 0;

  struct request_context_small req_ctx = {};
  req_ctx.app_request_id = generate_request_id(pid_tgid);
  req_ctx.original_size = ctx->args[2];
  req_ctx.timestamp = bpf_ktime_get_ns();
  req_ctx.system_type = detect_system_type(comm);
  req_ctx.is_minio = trace_this;

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
  event->event_type = trace_this ? EVENT_MINIO_OBJECT_GET : EVENT_APP_READ;
  event->system_type = req_ctx.system_type;
  event->size = req_ctx.original_size;
  event->request_id = req_ctx.app_request_id;
  event->aligned_size = req_ctx.original_size;
  event->latency_ns = 0;
  event->is_minio = trace_this;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// MinIO-specific tracing for open/openat to capture file patterns
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_minio_openat(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_minio_process(comm, pid))
    return 0;

  // Get temp storage for filename
  u32 temp_key = 0;
  struct temp_storage *temp = bpf_map_lookup_elem(&temp_storage_map, &temp_key);
  if (!temp)
    return 0;

  // Try to read filename
  const char *filename_ptr = (const char *)ctx->args[1];
  bpf_probe_read_user_str(temp->filename, sizeof(temp->filename), filename_ptr);

  // Check if it's a MinIO-specific file
  bool is_xl_meta = false;
  bool is_part_file = false;

#pragma unroll
  for (int i = 0; i < 64; i++) { // Check first 64 chars
    if (i + 7 < MAX_FILENAME_LEN) {
      if (temp->filename[i] == 'x' && temp->filename[i + 1] == 'l' &&
          temp->filename[i + 2] == '.' && temp->filename[i + 3] == 'm' &&
          temp->filename[i + 4] == 'e' && temp->filename[i + 5] == 't' &&
          temp->filename[i + 6] == 'a') {
        is_xl_meta = true;
        break;
      }
    }
    if (i + 5 < MAX_FILENAME_LEN) {
      if (temp->filename[i] == 'p' && temp->filename[i + 1] == 'a' &&
          temp->filename[i + 2] == 'r' && temp->filename[i + 3] == 't' &&
          temp->filename[i + 4] == '.') {
        is_part_file = true;
        break;
      }
    }
  }

  if (is_xl_meta || is_part_file) {
    struct multilayer_io_event *event =
        bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
      return 0;

    init_event(event);

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->layer = LAYER_STORAGE_SERVICE;
    event->event_type =
        is_xl_meta ? EVENT_MINIO_XL_META : EVENT_MINIO_ERASURE_WRITE;
    event->system_type = SYSTEM_TYPE_MINIO;
    event->is_minio = 1;
    event->is_xl_meta = is_xl_meta;
    event->is_metadata = is_xl_meta;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

// Copy filename to event
#pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN && i < sizeof(event->filename); i++) {
      event->filename[i] = temp->filename[i];
    }

    bpf_ringbuf_submit(event, 0);
  }

  return 0;
}

// ============================================================================
// LAYER 3: OPERATING SYSTEM LAYER - VFS operations
// ============================================================================

SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  size_t count = PT_REGS_PARM3(ctx);

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Check MinIO filtering
  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);
  if (config && config->trace_mode != MINIO_TRACE_OFF) {
    if (!is_minio_process(comm, pid))
      return 0;
  }

  struct request_context_small *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

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

  // Try to get inode safely
  if (file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
      event->inode = BPF_CORE_READ(inode, i_ino);
    }
  }

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->system_type = req_ctx->system_type;
    event->is_minio = req_ctx->is_minio;
  }

  // Calculate aligned size (round up to 4KB page)
  event->aligned_size = (count + 4095) & ~4095ULL;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  size_t count = PT_REGS_PARM3(ctx);

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Check MinIO filtering
  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);
  if (config && config->trace_mode != MINIO_TRACE_OFF) {
    if (!is_minio_process(comm, pid))
      return 0;
  }

  struct request_context_small *req_ctx =
      bpf_map_lookup_elem(&request_tracking, &pid_tgid);

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

  if (file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
      event->inode = BPF_CORE_READ(inode, i_ino);
    }
  }

  if (req_ctx) {
    event->request_id = req_ctx->app_request_id;
    event->system_type = req_ctx->system_type;
    event->is_minio = req_ctx->is_minio;

    // For MinIO, track erasure coding amplification
    if (req_ctx->is_minio && req_ctx->erasure_blocks > 0) {
      event->erasure_set_index = req_ctx->erasure_blocks;
    }
  }

  // Calculate aligned size
  event->aligned_size = (count + 4095) & ~4095ULL;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// LAYER 4: FILESYSTEM LAYER - Track sync operations
// ============================================================================

SEC("kprobe/vfs_fsync_range")
int trace_fs_sync(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Check MinIO filtering
  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);
  if (config && config->trace_mode != MINIO_TRACE_OFF) {
    if (!is_minio_process(comm, pid))
      return 0;
  }

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
  event->is_metadata = 1; // Sync is metadata operation
  event->is_journal = 0;
  event->is_minio = is_minio_process(comm, pid);

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

// ============================================================================
// MinIO-specific splice tracking (for multipart uploads)
// ============================================================================

SEC("kprobe/do_splice_direct")
int trace_minio_splice(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_minio_process(comm, pid))
    return 0;

  loff_t len = PT_REGS_PARM3(ctx);

  struct multilayer_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
  if (!event)
    return 0;

  init_event(event);

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = (u32)pid_tgid;
  event->layer = LAYER_STORAGE_SERVICE;
  event->event_type = EVENT_MINIO_MULTIPART;
  event->system_type = SYSTEM_TYPE_MINIO;
  event->size = len;
  event->is_minio = 1;

  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);

  return 0;
}

// ============================================================================
// LAYER 5: DEVICE LAYER - Block I/O
// ============================================================================

SEC("kprobe/submit_bio")
int trace_bio_submit(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);

  if (!bio)
    return 0;

  char comm[MAX_COMM_LEN] = {};
  bpf_get_current_comm(comm, sizeof(comm));

  // Check MinIO filtering
  u32 key = 0;
  struct minio_config *config = bpf_map_lookup_elem(&minio_config_map, &key);
  if (config && config->trace_mode != MINIO_TRACE_OFF) {
    if (!is_minio_process(comm, pid))
      return 0;
  }

  struct request_context_small *req_ctx =
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

  // Safely read bio fields
  unsigned int bi_size = BPF_CORE_READ(bio, bi_iter.bi_size);
  sector_t bi_sector = BPF_CORE_READ(bio, bi_iter.bi_sector);

  event->size = bi_size;
  event->aligned_size = bi_size;   // Block I/O is already aligned
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
    event->is_minio = req_ctx->is_minio;
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

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&io_start_times, &bio_addr);

  return 0;
}

char _license[] SEC("license") = "GPL";
