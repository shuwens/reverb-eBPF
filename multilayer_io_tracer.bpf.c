// Fixed Multi-Layer I/O Tracer - Corrected version
// File: multilayer_io_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
#define EVENT_APP_READ 101
#define EVENT_APP_WRITE 102
#define EVENT_OS_VFS_READ 303
#define EVENT_OS_VFS_WRITE 304
#define EVENT_FS_SYNC 401
#define EVENT_DEV_BIO_SUBMIT 501
#define EVENT_DEV_BIO_COMPLETE 502

// Storage system types
#define SYSTEM_TYPE_UNKNOWN 0
#define SYSTEM_TYPE_MINIO 1
#define SYSTEM_TYPE_CEPH 2
#define SYSTEM_TYPE_ETCD 3
#define SYSTEM_TYPE_POSTGRES 4
#define SYSTEM_TYPE_GLUSTER 5
#define SYSTEM_TYPE_APPLICATION 6

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

struct request_context {
    u64 app_request_id;
    u64 original_size;
    u64 timestamp;
    u32 system_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct request_context);
} request_tracking SEC(".maps");

// Helper to detect storage system type
static __always_inline u32 detect_system_type(const char *comm) {
    for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
        if (comm[i] == 'm' && comm[i+1] == 'i' && comm[i+2] == 'n' && comm[i+3] == 'i')
            return SYSTEM_TYPE_MINIO;
        if (comm[i] == 'c' && comm[i+1] == 'e' && comm[i+2] == 'p' && comm[i+3] == 'h')
            return SYSTEM_TYPE_CEPH;
        if (comm[i] == 'e' && comm[i+1] == 't' && comm[i+2] == 'c' && comm[i+3] == 'd')
            return SYSTEM_TYPE_ETCD;
        if (comm[i] == 'p' && comm[i+1] == 'o' && comm[i+2] == 's' && comm[i+3] == 't')
            return SYSTEM_TYPE_POSTGRES;
        if (comm[i] == 'g' && comm[i+1] == 'l' && comm[i+2] == 'u' && comm[i+3] == 's')
            return SYSTEM_TYPE_GLUSTER;
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
// LAYER 1: APPLICATION LAYER - Using tracepoints (most reliable)
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_write")
int trace_app_write_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    
    struct request_context req_ctx = {};
    req_ctx.app_request_id = generate_request_id(pid_tgid);
    req_ctx.original_size = ctx->args[2];
    req_ctx.timestamp = bpf_ktime_get_ns();
    req_ctx.system_type = detect_system_type(comm);
    
    bpf_map_update_elem(&request_tracking, &pid_tgid, &req_ctx, BPF_ANY);
    bpf_map_update_elem(&io_start_times, &pid_tgid, &req_ctx.timestamp, BPF_ANY);
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
        return 0;
    
    // Initialize all fields to zero first
    init_event(event);
    
    event->timestamp = req_ctx.timestamp;
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->layer = LAYER_APPLICATION;
    event->event_type = EVENT_APP_WRITE;
    event->system_type = req_ctx.system_type;
    event->size = req_ctx.original_size;
    event->request_id = req_ctx.app_request_id;
    event->aligned_size = req_ctx.original_size;  // No alignment at app layer
    event->latency_ns = 0;
    event->offset = 0;
    event->is_metadata = 0;
    event->is_journal = 0;
    event->cache_hit = 0;
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
    
    struct request_context req_ctx = {};
    req_ctx.app_request_id = generate_request_id(pid_tgid);
    req_ctx.original_size = ctx->args[2];
    req_ctx.timestamp = bpf_ktime_get_ns();
    req_ctx.system_type = detect_system_type(comm);
    
    bpf_map_update_elem(&request_tracking, &pid_tgid, &req_ctx, BPF_ANY);
    bpf_map_update_elem(&io_start_times, &pid_tgid, &req_ctx.timestamp, BPF_ANY);
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
        return 0;
    
    init_event(event);
    
    event->timestamp = req_ctx.timestamp;
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->layer = LAYER_APPLICATION;
    event->event_type = EVENT_APP_READ;
    event->system_type = req_ctx.system_type;
    event->size = req_ctx.original_size;
    event->request_id = req_ctx.app_request_id;
    event->aligned_size = req_ctx.original_size;
    event->latency_ns = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// LAYER 3: OPERATING SYSTEM LAYER - VFS operations
// ============================================================================

SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    
    struct request_context *req_ctx = bpf_map_lookup_elem(&request_tracking, &pid_tgid);
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
        return 0;
    
    init_event(event);
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
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
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    
    struct request_context *req_ctx = bpf_map_lookup_elem(&request_tracking, &pid_tgid);
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
        return 0;
    
    init_event(event);
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
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
    }
    
    // Calculate aligned size
    event->aligned_size = (count + 4095) & ~4095ULL;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// LAYER 4: FILESYSTEM LAYER - Simplified to just track sync operations
// ============================================================================

SEC("kprobe/vfs_fsync_range")
int trace_fs_sync(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
        return 0;
    
    init_event(event);
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->layer = LAYER_FILESYSTEM;
    event->event_type = EVENT_FS_SYNC;
    event->size = 0;
    event->aligned_size = 0;
    event->is_metadata = 1;  // Sync is metadata operation
    event->is_journal = 0;
    
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
    struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
    
    if (!bio)
        return 0;
    
    struct request_context *req_ctx = bpf_map_lookup_elem(&request_tracking, &pid_tgid);
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
    if (!event)
        return 0;
    
    init_event(event);
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->layer = LAYER_DEVICE;
    event->event_type = EVENT_DEV_BIO_SUBMIT;
    
    // Safely read bio fields
    unsigned int bi_size = BPF_CORE_READ(bio, bi_iter.bi_size);
    sector_t bi_sector = BPF_CORE_READ(bio, bi_iter.bi_sector);
    
    event->size = bi_size;
    event->aligned_size = bi_size;  // Block I/O is already aligned
    event->offset = bi_sector * 512;  // Convert sectors to bytes
    
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
    
    if (!bio)
        return 0;
        
    u64 bio_addr = (u64)bio;
    
    u64 *start_time = bpf_map_lookup_elem(&io_start_times, &bio_addr);
    if (!start_time)
        return 0;
    
    u64 latency = bpf_ktime_get_ns() - *start_time;
    
    struct multilayer_io_event *event = bpf_ringbuf_reserve(&events, sizeof(struct multilayer_io_event), 0);
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

