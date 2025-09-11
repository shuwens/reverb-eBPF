// Enhanced Multi-Layer I/O Tracer with MinIO-specific tracking - Userspace
// program File: multilayer_io_tracer.c

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// Include the auto-generated skeleton
#include "multilayer_io_tracer.skel.h"

#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_BUCKET_NAME_LEN 64

// Layer definitions (must match BPF program)
#define LAYER_APPLICATION 1
#define LAYER_STORAGE_SERVICE 2
#define LAYER_OPERATING_SYSTEM 3
#define LAYER_FILESYSTEM 4
#define LAYER_DEVICE 5

// MinIO tracking modes
#define MINIO_TRACE_OFF 0
#define MINIO_TRACE_NAME 1
#define MINIO_TRACE_PID 2
#define MINIO_TRACE_ALL 3

// Must match the BPF program's struct exactly
struct multilayer_io_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u8 layer;
  __u32 event_type;
  __u32 system_type;
  __u64 size;
  __u64 offset;
  __u64 latency_ns;
  __u32 dev_major;
  __u32 dev_minor;
  __s32 retval;
  __u64 inode;
  __u64 request_id;
  char comm[MAX_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  __u64 aligned_size;
  __u32 replication_count;
  __u32 block_count;
  __u8 is_metadata;
  __u8 is_journal;
  __u8 cache_hit;

  // MinIO-specific fields
  __u32 erasure_set_index;
  __u32 erasure_block_index;
  __u8 is_parity_block;
  __u8 is_xl_meta;
  __u32 object_part_number;
  char bucket_name[MAX_BUCKET_NAME_LEN];
  __u8 is_minio;
};

struct minio_config {
  __u8 trace_mode;
  __u8 trace_erasure;
  __u8 trace_metadata;
  __u8 verbose;
};

// Storage system types
const char *system_names[] = {"Unknown",    "MinIO",     "Ceph",       "etcd",
                              "PostgreSQL", "GlusterFS", "Application"};

const char *layer_names[] = {"UNKNOWN", "APPLICATION", "STORAGE_SVC",
                             "OS",      "FILESYSTEM",  "DEVICE"};

// Per-layer statistics
struct layer_stats {
  __u64 total_events;
  __u64 total_bytes;
  __u64 aligned_bytes;
  __u64 metadata_ops;
  __u64 journal_ops;
  __u64 cache_hits;
  __u64 cache_misses;
  __u64 total_latency;
  double amplification_factor;

  // MinIO-specific stats
  __u64 minio_events;
  __u64 minio_bytes;
  __u64 xl_meta_ops;
  __u64 erasure_writes;
  __u64 multipart_ops;
};

// MinIO-specific statistics
struct minio_stats {
  __u64 total_objects_written;
  __u64 total_objects_read;
  __u64 xl_meta_operations;
  __u64 erasure_blocks_written;
  __u64 multipart_uploads;
  __u64 total_erasure_amplification;
  __u64 metadata_bytes;
  __u64 data_bytes;
  double erasure_overhead_factor;
};

// Per-request tracking for correlation
struct request_stats {
  __u64 request_id;
  __u64 app_size;
  __u64 storage_service_size;
  __u64 os_size;
  __u64 fs_size;
  __u64 device_size;
  __u32 replication_factor;
  __u32 journal_blocks;
  __u64 total_amplification;
  __u8 is_minio;
  char object_name[MAX_FILENAME_LEN];
};

static struct layer_stats stats[6] = {0}; // One per layer + unknown
static struct minio_stats minio_stats = {0};
static struct env {
  bool verbose;
  bool json_output;
  bool realtime;
  bool correlation_mode;
  int duration;
  const char *output_file;
  const char *trace_system;

  // MinIO-specific options
  bool minio_only;
  bool auto_detect_minio;
  int minio_pid;
  const char *minio_data_dir;
  bool trace_erasure;
  bool trace_metadata;
  int minio_port;
} env = {
    .verbose = false,
    .json_output = false,
    .realtime = true,
    .correlation_mode = false,
    .duration = 0,
    .output_file = NULL,
    .trace_system = NULL,
    .minio_only = false,
    .auto_detect_minio = false,
    .minio_pid = -1,
    .minio_data_dir = NULL,
    .trace_erasure = false,
    .trace_metadata = false,
    .minio_port = 9000,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"json", 'j', NULL, 0, "Output in JSON format"},
    {"duration", 'd', "DURATION", 0, "Trace for specified duration (seconds)"},
    {"output", 'o', "FILE", 0, "Output to file instead of stdout"},
    {"quiet", 'q', NULL, 0, "Disable real-time output, only show summary"},
    {"correlate", 'c', NULL, 0, "Enable request correlation mode"},
    {"system", 's', "SYSTEM", 0,
     "Trace specific storage system (minio/ceph/etcd/postgres/gluster)"},

    // MinIO-specific options
    {0, 0, 0, 0, "MinIO-specific options:"},
    {"minio-only", 'M', NULL, 0, "Trace only MinIO processes"},
    {"auto-detect-minio", 'A', NULL, 0,
     "Auto-detect and trace all MinIO processes"},
    {"minio-pid", 'p', "PID", 0, "Trace specific MinIO PID"},
    {"minio-data-dir", 'D', "DIR", 0, "MinIO data directory to monitor"},
    {"trace-erasure", 'E', NULL, 0, "Trace MinIO erasure coding operations"},
    {"trace-metadata", 'T', NULL, 0,
     "Trace MinIO metadata operations (xl.meta)"},
    {"minio-port", 'P', "PORT", 0, "MinIO port (default: 9000)"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  switch (key) {
  case 'v':
    env.verbose = true;
    break;
  case 'j':
    env.json_output = true;
    break;
  case 'd':
    env.duration = atoi(arg);
    break;
  case 'o':
    env.output_file = arg;
    break;
  case 'q':
    env.realtime = false;
    break;
  case 'c':
    env.correlation_mode = true;
    break;
  case 's':
    env.trace_system = arg;
    if (strcasecmp(arg, "minio") == 0) {
      env.minio_only = true;
    }
    break;
  case 'M':
    env.minio_only = true;
    break;
  case 'A':
    env.auto_detect_minio = true;
    env.minio_only = true;
    break;
  case 'p':
    env.minio_pid = atoi(arg);
    env.minio_only = true;
    break;
  case 'D':
    env.minio_data_dir = arg;
    break;
  case 'E':
    env.trace_erasure = true;
    break;
  case 'T':
    env.trace_metadata = true;
    break;
  case 'P':
    env.minio_port = atoi(arg);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "Multi-layer I/O tracer with enhanced MinIO support\n"
           "\nExamples:\n"
           "  # Trace all I/O operations:\n"
           "  sudo ./multilayer_io_tracer\n"
           "\n"
           "  # Trace only MinIO with auto-detection:\n"
           "  sudo ./multilayer_io_tracer -A -v\n"
           "\n"
           "  # Trace specific MinIO PID with correlation:\n"
           "  sudo ./multilayer_io_tracer -p $(pgrep minio) -c -E -T\n"
           "\n"
           "  # Trace MinIO with erasure coding and metadata tracking:\n"
           "  sudo ./multilayer_io_tracer -M -E -T -o minio_trace.log\n",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;

// Request correlation tracking
#define MAX_REQUESTS 10000
static struct request_stats requests[MAX_REQUESTS];
static int request_count = 0;

// Forward declarations
static void print_amplification_summary(void);
static void print_minio_summary(void);
static int find_minio_processes(struct multilayer_io_tracer_bpf *skel);
static int add_minio_pid(struct multilayer_io_tracer_bpf *skel, __u32 pid);

// Modified signal handler that prints summary before exiting
static void sig_handler(int sig) {
  if (!exiting) {
    exiting = true;

    // Print summary when interrupted
    if (output_fp) {
      fprintf(output_fp, "\n=== Tracer interrupted, generating summary ===\n");
      print_amplification_summary();
      if (env.minio_only) {
        print_minio_summary();
      }
      fflush(output_fp);
    }
  }
}

const char *get_event_name(__u32 event_type) {
  switch (event_type) {
  // Application layer
  case 101:
    return "APP_READ";
  case 102:
    return "APP_WRITE";
  case 103:
    return "APP_OPEN";
  case 104:
    return "APP_CLOSE";
  case 105:
    return "APP_FSYNC";

  // MinIO-specific events
  case 201:
    return "MINIO_OBJECT_PUT";
  case 202:
    return "MINIO_OBJECT_GET";
  case 203:
    return "MINIO_ERASURE_WRITE";
  case 204:
    return "MINIO_METADATA_UPDATE";
  case 205:
    return "MINIO_BITROT_CHECK";
  case 206:
    return "MINIO_MULTIPART";
  case 207:
    return "MINIO_XL_META";

  // OS layer
  case 301:
    return "OS_SYSCALL_ENTER";
  case 302:
    return "OS_SYSCALL_EXIT";
  case 303:
    return "OS_VFS_READ";
  case 304:
    return "OS_VFS_WRITE";
  case 305:
    return "OS_PAGE_CACHE_HIT";
  case 306:
    return "OS_PAGE_CACHE_MISS";
  case 307:
    return "OS_CONTEXT_SWITCH";

  // Filesystem layer
  case 401:
    return "FS_SYNC";
  case 402:
    return "FS_METADATA_UPDATE";
  case 403:
    return "FS_DATA_WRITE";
  case 404:
    return "FS_INODE_UPDATE";
  case 405:
    return "FS_EXTENT_ALLOC";
  case 406:
    return "FS_BLOCK_ALLOC";

  // Device layer
  case 501:
    return "DEV_BIO_SUBMIT";
  case 502:
    return "DEV_BIO_COMPLETE";
  case 503:
    return "DEV_REQUEST_QUEUE";
  case 504:
    return "DEV_REQUEST_COMPLETE";
  case 505:
    return "DEV_FTL_WRITE";
  case 506:
    return "DEV_TRIM";

  default:
    return "UNKNOWN";
  }
}

static void update_stats(const struct multilayer_io_event *e) {
  if (e->layer > 5)
    return;

  struct layer_stats *s = &stats[e->layer];
  s->total_events++;
  s->total_bytes += e->size;
  s->aligned_bytes += e->aligned_size ? e->aligned_size : e->size;

  if (e->is_metadata)
    s->metadata_ops++;
  if (e->is_journal)
    s->journal_ops++;
  if (e->cache_hit)
    s->cache_hits++;
  if (e->event_type == 306)
    s->cache_misses++;

  s->total_latency += e->latency_ns;

  // Update MinIO-specific stats
  if (e->is_minio) {
    s->minio_events++;
    s->minio_bytes += e->size;

    if (e->is_xl_meta) {
      s->xl_meta_ops++;
      minio_stats.xl_meta_operations++;
      minio_stats.metadata_bytes += e->size;
    }

    if (e->event_type == 203) { // MINIO_ERASURE_WRITE
      s->erasure_writes++;
      minio_stats.erasure_blocks_written++;
    }

    if (e->event_type == 206) { // MINIO_MULTIPART
      s->multipart_ops++;
      minio_stats.multipart_uploads++;
    }

    if (e->event_type == 201) { // MINIO_OBJECT_PUT
      minio_stats.total_objects_written++;
      minio_stats.data_bytes += e->size;
    }

    if (e->event_type == 202) { // MINIO_OBJECT_GET
      minio_stats.total_objects_read++;
    }
  }

  // Update request correlation if enabled
  if (env.correlation_mode && e->request_id != 0) {
    for (int i = 0; i < request_count; i++) {
      if (requests[i].request_id == e->request_id) {
        switch (e->layer) {
        case LAYER_APPLICATION:
          requests[i].app_size += e->size;
          requests[i].is_minio = e->is_minio;
          break;
        case LAYER_STORAGE_SERVICE:
          requests[i].storage_service_size += e->size;
          if (e->replication_count > 0)
            requests[i].replication_factor = e->replication_count;
          break;
        case LAYER_OPERATING_SYSTEM:
          requests[i].os_size += e->aligned_size ? e->aligned_size : e->size;
          break;
        case LAYER_FILESYSTEM:
          requests[i].fs_size += e->size;
          if (e->is_journal)
            requests[i].journal_blocks += e->block_count;
          break;
        case LAYER_DEVICE:
          requests[i].device_size += e->size;
          break;
        }
        return;
      }
    }

    // New request
    if (request_count < MAX_REQUESTS && e->layer == LAYER_APPLICATION) {
      requests[request_count].request_id = e->request_id;
      requests[request_count].app_size = e->size;
      requests[request_count].is_minio = e->is_minio;
      if (e->filename[0] != '\0') {
        strncpy(requests[request_count].object_name, e->filename,
                MAX_FILENAME_LEN - 1);
      }
      request_count++;
    }
  }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct multilayer_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  update_stats(e);

  if (!env.realtime)
    return 0;

  t = e->timestamp / 1000000000;
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (env.json_output) {
    fprintf(output_fp,
            "{\"timestamp\":\"%s.%09llu\","
            "\"layer\":\"%s\","
            "\"event\":\"%s\","
            "\"pid\":%u,"
            "\"comm\":\"%s\","
            "\"system\":\"%s\","
            "\"size\":%llu,"
            "\"aligned_size\":%llu,"
            "\"latency_us\":%.2f,"
            "\"request_id\":\"%016llx\","
            "\"is_metadata\":%d,"
            "\"is_journal\":%d,"
            "\"cache_hit\":%d,"
            "\"is_minio\":%d,"
            "\"is_xl_meta\":%d,"
            "\"filename\":\"%s\"}\n",
            ts, e->timestamp % 1000000000, layer_names[e->layer],
            get_event_name(e->event_type), e->pid, e->comm,
            system_names[e->system_type], e->size, e->aligned_size,
            e->latency_ns / 1000.0, e->request_id, e->is_metadata,
            e->is_journal, e->cache_hit, e->is_minio, e->is_xl_meta,
            e->filename);
  } else {
    // Color coding for MinIO events
    const char *color_start = "";
    const char *color_end = "";
    if (e->is_minio && isatty(fileno(output_fp))) {
      color_start = "\033[1;36m"; // Cyan for MinIO
      color_end = "\033[0m";
    }

    fprintf(output_fp,
            "%s%s.%03llu %-12s %-25s %7llu %7llu %8.2f %-15s %s%s%s%s%s%s\n",
            color_start, ts, (e->timestamp % 1000000000) / 1000000,
            layer_names[e->layer], get_event_name(e->event_type), e->size,
            e->aligned_size ? e->aligned_size : e->size, e->latency_ns / 1000.0,
            e->comm, e->is_metadata ? "[META]" : "",
            e->is_journal ? "[JRNL]" : "", e->cache_hit ? "[HIT]" : "",
            e->is_minio ? "[MINIO]" : "", e->is_xl_meta ? "[XL.META]" : "",
            color_end);

    // Print filename if present and verbose
    if (env.verbose && e->filename[0] != '\0') {
      fprintf(output_fp, "    └─> File: %s\n", e->filename);
    }
  }

  fflush(output_fp);
  return 0;
}

static void print_header() {
  if (env.json_output || !env.realtime)
    return;

  fprintf(output_fp, "%-16s %-12s %-25s %7s %7s %8s %-15s %s\n", "TIME",
          "LAYER", "EVENT", "SIZE", "ALIGNED", "LAT(μs)", "COMM", "FLAGS");
  fprintf(output_fp, "========================================================="
                     "===============\n");

  if (env.minio_only) {
    fprintf(output_fp, ">>> TRACING MINIO PROCESSES ONLY <<<\n");
    fprintf(output_fp,
            "========================================================="
            "===============\n");
  }
}

static void print_amplification_summary() {
  fprintf(output_fp, "\n========================================\n");
  fprintf(output_fp, "    I/O AMPLIFICATION ANALYSIS\n");
  fprintf(output_fp, "========================================\n\n");

  // Calculate amplification factors
  if (stats[LAYER_APPLICATION].total_bytes > 0) {
    for (int i = 2; i <= 5; i++) {
      stats[i].amplification_factor =
          (double)stats[i].aligned_bytes / stats[LAYER_APPLICATION].total_bytes;
    }
  }

  fprintf(output_fp, "Per-Layer Statistics:\n");
  fprintf(output_fp, "%-15s %10s %10s %10s %8s %8s %8s %10s\n", "LAYER",
          "EVENTS", "BYTES", "ALIGNED", "META", "JRNL", "CACHE", "AMP_FACTOR");
  fprintf(output_fp, "---------------------------------------------------------"
                     "-------------\n");

  for (int i = 1; i <= 5; i++) {
    struct layer_stats *s = &stats[i];
    fprintf(output_fp, "%-15s %10llu %10llu %10llu %8llu %8llu %8llu %10.2fx\n",
            layer_names[i], s->total_events, s->total_bytes, s->aligned_bytes,
            s->metadata_ops, s->journal_ops, s->cache_hits,
            s->amplification_factor);

    // Show MinIO-specific stats if present
    if (s->minio_events > 0) {
      fprintf(
          output_fp, "  └─> MinIO:    %10llu %10llu %10s %8llu %8s %8s %10s\n",
          s->minio_events, s->minio_bytes, "-", s->xl_meta_ops, "-", "-", "-");
    }
  }

  fprintf(output_fp, "\nAmplification Breakdown:\n");
  fprintf(output_fp, "---------------------------------------------------------"
                     "-------------\n");

  if (stats[LAYER_APPLICATION].total_bytes > 0) {
    __u64 app_bytes = stats[LAYER_APPLICATION].total_bytes;

    fprintf(output_fp, "Original application I/O:     %10llu bytes\n",
            app_bytes);

    if (stats[LAYER_STORAGE_SERVICE].total_bytes > 0) {
      fprintf(
          output_fp,
          "After storage service layer:  %10llu bytes (%.2fx amplification)\n",
          stats[LAYER_STORAGE_SERVICE].aligned_bytes,
          (double)stats[LAYER_STORAGE_SERVICE].aligned_bytes / app_bytes);
    }

    if (stats[LAYER_OPERATING_SYSTEM].aligned_bytes > 0) {
      fprintf(
          output_fp,
          "After OS/page cache alignment:%10llu bytes (%.2fx amplification)\n",
          stats[LAYER_OPERATING_SYSTEM].aligned_bytes,
          (double)stats[LAYER_OPERATING_SYSTEM].aligned_bytes / app_bytes);
    }

    if (stats[LAYER_FILESYSTEM].total_bytes > 0) {
      __u64 fs_total = stats[LAYER_FILESYSTEM].aligned_bytes;
      fprintf(
          output_fp,
          "After filesystem layer:       %10llu bytes (%.2fx amplification)\n",
          fs_total, (double)fs_total / app_bytes);
      fprintf(output_fp, "  - Journal writes:           %10llu bytes\n",
              stats[LAYER_FILESYSTEM].journal_ops * 4096);
      fprintf(output_fp, "  - Metadata updates:         %10llu operations\n",
              stats[LAYER_FILESYSTEM].metadata_ops);
    }

    if (stats[LAYER_DEVICE].total_bytes > 0) {
      fprintf(
          output_fp,
          "Final device layer I/O:       %10llu bytes (%.2fx amplification)\n",
          stats[LAYER_DEVICE].total_bytes,
          (double)stats[LAYER_DEVICE].total_bytes / app_bytes);
    }

    // Calculate total amplification
    __u64 final_bytes = stats[LAYER_DEVICE].total_bytes;
    if (final_bytes == 0)
      final_bytes = stats[LAYER_FILESYSTEM].total_bytes;
    if (final_bytes == 0)
      final_bytes = stats[LAYER_OPERATING_SYSTEM].aligned_bytes;

    if (final_bytes > 0) {
      fprintf(output_fp, "\n*** TOTAL AMPLIFICATION: %.2fx ***\n",
              (double)final_bytes / app_bytes);
      fprintf(output_fp, "    %llu bytes written for %llu bytes requested\n",
              final_bytes, app_bytes);
    }
  }

  // Per-request analysis if correlation mode is enabled
  if (env.correlation_mode && request_count > 0) {
    fprintf(output_fp, "\n\nPer-Request Amplification (Top 10):\n");
    fprintf(output_fp, "%-16s %8s %8s %8s %8s %8s %8s %6s %7s\n", "REQUEST_ID",
            "APP", "STORAGE", "OS", "FS", "DEVICE", "TOTAL", "AMP", "MinIO");
    fprintf(output_fp, "-------------------------------------------------------"
                       "----------------------\n");

    int display_count = request_count > 10 ? 10 : request_count;
    for (int i = 0; i < display_count; i++) {
      struct request_stats *r = &requests[i];
      __u64 total = r->device_size ? r->device_size : r->fs_size;
      if (total == 0)
        total = r->os_size;

      double amp = r->app_size > 0 ? (double)total / r->app_size : 0;

      fprintf(
          output_fp, "%016llx %8llu %8llu %8llu %8llu %8llu %8llu %6.2fx %7s\n",
          r->request_id, r->app_size, r->storage_service_size, r->os_size,
          r->fs_size, r->device_size, total, amp, r->is_minio ? "Yes" : "No");
    }
  }
}

static void print_minio_summary() {
  fprintf(output_fp, "\n========================================\n");
  fprintf(output_fp, "       MinIO-SPECIFIC ANALYSIS\n");
  fprintf(output_fp, "========================================\n\n");

  fprintf(output_fp, "MinIO Operation Statistics:\n");
  fprintf(output_fp, "-------------------------------------------\n");
  fprintf(output_fp, "Objects Written:           %10llu\n",
          minio_stats.total_objects_written);
  fprintf(output_fp, "Objects Read:              %10llu\n",
          minio_stats.total_objects_read);
  fprintf(output_fp, "XL Metadata Operations:    %10llu\n",
          minio_stats.xl_meta_operations);
  fprintf(output_fp, "Erasure Blocks Written:    %10llu\n",
          minio_stats.erasure_blocks_written);
  fprintf(output_fp, "Multipart Uploads:         %10llu\n",
          minio_stats.multipart_uploads);
  fprintf(output_fp, "\n");

  fprintf(output_fp, "MinIO Data Breakdown:\n");
  fprintf(output_fp, "-------------------------------------------\n");
  fprintf(output_fp, "Data Bytes:                %10llu\n",
          minio_stats.data_bytes);
  fprintf(output_fp, "Metadata Bytes:            %10llu\n",
          minio_stats.metadata_bytes);

  if (minio_stats.data_bytes > 0) {
    double metadata_overhead =
        (double)minio_stats.metadata_bytes / minio_stats.data_bytes * 100.0;
    fprintf(output_fp, "Metadata Overhead:         %9.2f%%\n",
            metadata_overhead);
  }

  // Calculate erasure coding overhead if applicable
  if (minio_stats.erasure_blocks_written > 0 &&
      minio_stats.total_objects_written > 0) {
    double avg_erasure_blocks = (double)minio_stats.erasure_blocks_written /
                                minio_stats.total_objects_written;
    fprintf(output_fp, "Avg Erasure Blocks/Object: %10.2f\n",
            avg_erasure_blocks);

    // Estimate erasure overhead (typical MinIO uses 4+2 or 8+4 erasure coding)
    if (avg_erasure_blocks > 4) {
      double erasure_overhead =
          (avg_erasure_blocks / 4.0) - 1.0; // Assuming 4 data blocks
      fprintf(output_fp, "Erasure Coding Overhead:   %9.2f%%\n",
              erasure_overhead * 100.0);
    }
  }

  fprintf(output_fp, "\n");
  fprintf(output_fp, "MinIO I/O Pattern Analysis:\n");
  fprintf(output_fp, "-------------------------------------------\n");

  // Show per-layer MinIO activity
  for (int i = 1; i <= 5; i++) {
    if (stats[i].minio_events > 0) {
      fprintf(output_fp, "%-15s: %8llu events, %10llu bytes\n", layer_names[i],
              stats[i].minio_events, stats[i].minio_bytes);

      if (stats[i].xl_meta_ops > 0) {
        fprintf(output_fp, "  └─> XL.META operations: %llu\n",
                stats[i].xl_meta_ops);
      }
      if (stats[i].erasure_writes > 0) {
        fprintf(output_fp, "  └─> Erasure writes: %llu\n",
                stats[i].erasure_writes);
      }
      if (stats[i].multipart_ops > 0) {
        fprintf(output_fp, "  └─> Multipart operations: %llu\n",
                stats[i].multipart_ops);
      }
    }
  }

  // Calculate MinIO-specific amplification
  if (minio_stats.data_bytes > 0) {
    __u64 total_minio_io = 0;
    for (int i = 1; i <= 5; i++) {
      total_minio_io += stats[i].minio_bytes;
    }

    if (total_minio_io > minio_stats.data_bytes) {
      fprintf(output_fp, "\n*** MinIO Total I/O Amplification: %.2fx ***\n",
              (double)total_minio_io / minio_stats.data_bytes);
    }
  }
}

static int find_minio_processes(struct multilayer_io_tracer_bpf *skel) {
  FILE *fp;
  char cmd[256];
  __u32 pid;
  __u8 val = 1;
  int count = 0;

  // Find all MinIO processes
  fp = popen("pgrep -x minio", "r");
  if (fp) {
    while (fscanf(fp, "%u", &pid) == 1) {
      if (bpf_map_update_elem(bpf_map__fd(skel->maps.minio_pids), &pid, &val,
                              BPF_ANY) == 0) {
        if (env.verbose) {
          printf("Tracking MinIO PID: %u\n", pid);
        }
        count++;
      }
    }
    pclose(fp);
  }

  return count;
}

static int add_minio_pid(struct multilayer_io_tracer_bpf *skel, __u32 pid) {
  __u8 val = 1;

  if (bpf_map_update_elem(bpf_map__fd(skel->maps.minio_pids), &pid, &val,
                          BPF_ANY) == 0) {
    if (env.verbose) {
      printf("Added MinIO PID to tracking: %u\n", pid);
    }
    return 0;
  }

  return -1;
}

static int configure_minio_tracing(struct multilayer_io_tracer_bpf *skel) {
  struct minio_config config = {0};
  __u32 key = 0;

  // Set trace mode
  if (env.minio_only) {
    if (env.minio_pid > 0) {
      config.trace_mode = MINIO_TRACE_PID;
      add_minio_pid(skel, env.minio_pid);
    } else if (env.auto_detect_minio) {
      config.trace_mode = MINIO_TRACE_PID;
      int count = find_minio_processes(skel);
      if (count == 0) {
        fprintf(stderr, "Warning: No MinIO processes found. Falling back to "
                        "name-based detection.\n");
        config.trace_mode = MINIO_TRACE_NAME;
      } else {
        printf("Found %d MinIO process(es)\n", count);
      }
    } else {
      config.trace_mode = MINIO_TRACE_NAME;
    }
  } else {
    config.trace_mode = MINIO_TRACE_OFF;
  }

  config.trace_erasure = env.trace_erasure;
  config.trace_metadata = env.trace_metadata;
  config.verbose = env.verbose;

  // Update configuration in BPF map
  if (bpf_map_update_elem(bpf_map__fd(skel->maps.minio_config_map), &key,
                          &config, BPF_ANY) != 0) {
    fprintf(stderr, "Failed to update MinIO configuration\n");
    return -1;
  }

  if (env.verbose && env.minio_only) {
    printf("MinIO tracing configured:\n");
    printf("  Mode: %s\n", config.trace_mode == MINIO_TRACE_PID    ? "PID"
                           : config.trace_mode == MINIO_TRACE_NAME ? "Name"
                                                                   : "Off");
    printf("  Trace Erasure: %s\n", config.trace_erasure ? "Yes" : "No");
    printf("  Trace Metadata: %s\n", config.trace_metadata ? "Yes" : "No");
  }

  return 0;
}

static int bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct multilayer_io_tracer_bpf *skel;
  int err = 0;

  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  if (env.output_file) {
    output_fp = fopen(env.output_file, "w");
    if (!output_fp) {
      fprintf(stderr, "Failed to open output file %s: %s\n", env.output_file,
              strerror(errno));
      return 1;
    }
  } else {
    output_fp = stdout;
  }

  if (bump_memlock_rlimit()) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    return 1;
  }

  skel = multilayer_io_tracer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = multilayer_io_tracer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  // Configure MinIO tracing
  err = configure_minio_tracing(skel);
  if (err) {
    fprintf(stderr, "Failed to configure MinIO tracing\n");
    goto cleanup;
  }

  err = multilayer_io_tracer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  if (env.verbose) {
    fprintf(stderr, "Multi-layer I/O tracer started!\n");
    fprintf(stderr, "Tracing layers: Application, Storage Service, OS, "
                    "Filesystem, Device\n");
    if (env.trace_system)
      fprintf(stderr, "Filtering for system: %s\n", env.trace_system);
    if (env.minio_only)
      fprintf(stderr, "MinIO-only mode enabled\n");
    if (env.correlation_mode)
      fprintf(stderr, "Request correlation mode enabled\n");
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  print_header();

  time_t start_time = time(NULL);
  while (!exiting) {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
      break;
    }

    // Check duration limit
    if (env.duration > 0 && (time(NULL) - start_time) >= env.duration) {
      if (env.verbose)
        fprintf(stderr, "Tracing completed after %d seconds\n", env.duration);
      exiting = true; // Set flag instead of breaking
    }

    // Periodically refresh MinIO PIDs if auto-detect is enabled
    if (env.auto_detect_minio && (time(NULL) - start_time) % 10 == 0) {
      find_minio_processes(skel);
    }
  }

  // ALWAYS print summary before cleanup
  if (!exiting || output_fp) { // Print if we haven't already in signal handler
    print_amplification_summary();
    if (env.minio_only) {
      print_minio_summary();
    }
  }

cleanup:
  if (rb)
    ring_buffer__free(rb);
  if (skel)
    multilayer_io_tracer_bpf__destroy(skel);

  if (output_fp && output_fp != stdout) {
    fflush(output_fp);
    fclose(output_fp);
  }

  return err < 0 ? -err : 0;
}
