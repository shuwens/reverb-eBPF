// Multi-Layer I/O Tracer - Userspace program
// File: multilayer_io_tracer.c

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// Include the auto-generated skeleton
#include "multilayer_io_tracer.skel.h"

#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Layer definitions (must match BPF program)
#define LAYER_APPLICATION 1
#define LAYER_STORAGE_SERVICE 2
#define LAYER_OPERATING_SYSTEM 3
#define LAYER_FILESYSTEM 4
#define LAYER_DEVICE 5

// Storage system types
const char *system_names[] = {"Unknown",    "MinIO",     "Ceph",       "etcd",
                              "PostgreSQL", "GlusterFS", "Application"};

const char *layer_names[] = {"UNKNOWN", "APPLICATION", "STORAGE_SVC",
                             "OS",      "FILESYSTEM",  "DEVICE"};

struct io_event {
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

  // Additional metrics
  __u64 aligned_size;
  __u32 replication_count;
  __u32 block_count;
  __u8 is_metadata;
  __u8 is_journal;
  __u8 cache_hit;
};

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
};

static struct layer_stats stats[6] = {0}; // One per layer + unknown
static struct env {
  bool verbose;
  bool json_output;
  bool realtime;
  bool correlation_mode;
  int duration;
  const char *output_file;
  const char *trace_system; // Specific system to trace
} env = {
    .verbose = false,
    .json_output = false,
    .realtime = true,
    .correlation_mode = false,
    .duration = 0,
    .output_file = NULL,
    .trace_system = NULL,
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
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "Multi-layer I/O tracer for comprehensive storage stack analysis",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;

// Request correlation tracking
#define MAX_REQUESTS 10000
static struct request_stats requests[MAX_REQUESTS];
static int request_count = 0;

static void sig_handler(int sig) { exiting = true; }

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

  // Storage service layer
  case 201:
    return "STORAGE_REPLICATION";
  case 202:
    return "STORAGE_ERASURE_CODE";
  case 203:
    return "STORAGE_METADATA_UPDATE";
  case 204:
    return "STORAGE_CONSISTENCY_PROTOCOL";

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
    return "FS_JOURNAL_WRITE";
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

static void update_stats(const struct io_event *e) {
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
    s->cache_misses++; // EVENT_OS_PAGE_CACHE_MISS

  s->total_latency += e->latency_ns;

  // Update request correlation if enabled
  if (env.correlation_mode && e->request_id != 0) {
    for (int i = 0; i < request_count; i++) {
      if (requests[i].request_id == e->request_id) {
        switch (e->layer) {
        case LAYER_APPLICATION:
          requests[i].app_size += e->size;
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
      request_count++;
    }
  }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Filter by system if specified
  if (env.trace_system) {
    if (strcasecmp(env.trace_system, "minio") == 0 && e->system_type != 1)
      return 0;
    if (strcasecmp(env.trace_system, "ceph") == 0 && e->system_type != 2)
      return 0;
    if (strcasecmp(env.trace_system, "etcd") == 0 && e->system_type != 3)
      return 0;
    if (strcasecmp(env.trace_system, "postgres") == 0 && e->system_type != 4)
      return 0;
    if (strcasecmp(env.trace_system, "gluster") == 0 && e->system_type != 5)
      return 0;
  }

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
            "\"cache_hit\":%d}\n",
            ts, e->timestamp % 1000000000, layer_names[e->layer],
            get_event_name(e->event_type), e->pid, e->comm,
            system_names[e->system_type], e->size, e->aligned_size,
            e->latency_ns / 1000.0, e->request_id, e->is_metadata,
            e->is_journal, e->cache_hit);
  } else {
    fprintf(output_fp, "%s.%03llu %-12s %-25s %7llu %7llu %8.2f %-15s %s%s%s\n",
            ts, (e->timestamp % 1000000000) / 1000000, layer_names[e->layer],
            get_event_name(e->event_type), e->size,
            e->aligned_size ? e->aligned_size : e->size, e->latency_ns / 1000.0,
            e->comm, e->is_metadata ? "[META]" : "",
            e->is_journal ? "[JRNL]" : "", e->cache_hit ? "[HIT]" : "");
  }

  return 0;
}

static void print_header() {
  if (env.json_output || !env.realtime)
    return;

  fprintf(output_fp, "%-16s %-12s %-25s %7s %7s %8s %-15s %s\n", "TIME",
          "LAYER", "EVENT", "SIZE", "ALIGNED", "LAT(μs)", "COMM", "FLAGS");
  fprintf(output_fp, "%s\n",
          "="
          "="
          "="
          "="
          "="
          "="
          "="
          "="
          "="
          "="
          "="
          "=");
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
    fprintf(output_fp, "%-16s %8s %8s %8s %8s %8s %8s %6s\n", "REQUEST_ID",
            "APP", "STORAGE", "OS", "FS", "DEVICE", "TOTAL", "AMP");
    fprintf(output_fp, "-------------------------------------------------------"
                       "---------------\n");

    int display_count = request_count > 10 ? 10 : request_count;
    for (int i = 0; i < display_count; i++) {
      struct request_stats *r = &requests[i];
      __u64 total = r->device_size ? r->device_size : r->fs_size;
      if (total == 0)
        total = r->os_size;

      double amp = r->app_size > 0 ? (double)total / r->app_size : 0;

      fprintf(output_fp, "%016llx %8llu %8llu %8llu %8llu %8llu %8llu %6.2fx\n",
              r->request_id, r->app_size, r->storage_service_size, r->os_size,
              r->fs_size, r->device_size, total, amp);
    }
  }
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
  int err;

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

    if (env.duration > 0 && (time(NULL) - start_time) >= env.duration) {
      if (env.verbose)
        fprintf(stderr, "Tracing completed after %d seconds\n", env.duration);
      break;
    }
  }

  print_amplification_summary();

cleanup:
  ring_buffer__free(rb);
  multilayer_io_tracer_bpf__destroy(skel);

  if (output_fp != stdout)
    fclose(output_fp);

  return err < 0 ? -err : 0;
}
