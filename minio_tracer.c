// MinIO-specific Multi-Layer I/O Tracer - Userspace program
// File: minio_tracer.c

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
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
#include "minio_tracer.skel.h"

#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Layer definitions (must match BPF program)
#define LAYER_APPLICATION 1
#define LAYER_STORAGE_SERVICE 2
#define LAYER_OPERATING_SYSTEM 3
#define LAYER_FILESYSTEM 4
#define LAYER_DEVICE 5

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
  __u64 parent_request_id;
  __u32 branch_id;
  __u32 branch_count;
  char comm[MAX_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  __u64 aligned_size;
  __u32 replication_count;
  __u32 block_count;
  __u8 is_metadata;
  __u8 is_journal;
  __u8 cache_hit;
  __u8 is_erasure;
  __u8 erasure_data_blocks;
  __u8 erasure_parity_blocks;
};

// Request flow tracking
struct request_flow {
  __u64 request_id;
  __u64 parent_request_id;
  __u64 start_time;
  __u64 end_time;
  __u32 total_branches;
  __u32 completed_branches;

  // Per-layer metrics
  __u64 app_bytes;
  __u64 storage_bytes;
  __u64 os_bytes;
  __u64 fs_bytes;
  __u64 device_bytes;

  // Operation counts
  __u32 vfs_reads;
  __u32 vfs_writes;
  __u32 bio_submits;
  __u32 metadata_ops;
  __u32 journal_ops;

  // MinIO specific
  __u8 op_type; // 0=GET, 1=PUT
  char object_name[MAX_FILENAME_LEN];
  __u32 erasure_branches;
  __u32 replication_factor;
};

#define MAX_REQUESTS 10000
static struct request_flow requests[MAX_REQUESTS];
static int request_count = 0;

const char *layer_names[] = {"UNKNOWN", "APPLICATION", "STORAGE_SVC",
                             "OS",      "FILESYSTEM",  "DEVICE"};

static struct env {
  bool verbose;
  bool minio_only;
  bool show_branches;
  bool correlation_mode;
  int duration;
  const char *output_file;
} env = {
    .verbose = false,
    .minio_only = true,
    .show_branches = true,
    .correlation_mode = true,
    .duration = 0,
    .output_file = NULL,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"all", 'a', NULL, 0, "Trace all processes, not just MinIO"},
    {"no-branches", 'n', NULL, 0, "Hide branch information"},
    {"no-correlation", 'x', NULL, 0, "Disable request correlation"},
    {"duration", 'd', "DURATION", 0, "Trace for specified duration (seconds)"},
    {"output", 'o', "FILE", 0, "Output to file instead of stdout"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  switch (key) {
  case 'v':
    env.verbose = true;
    break;
  case 'a':
    env.minio_only = false;
    break;
  case 'n':
    env.show_branches = false;
    break;
  case 'x':
    env.correlation_mode = false;
    break;
  case 'd':
    env.duration = atoi(arg);
    break;
  case 'o':
    env.output_file = arg;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "MinIO-specific multi-layer I/O tracer with request correlation",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;

static void sig_handler(int sig) { exiting = true; }

const char *get_event_name(__u32 event_type) {
  switch (event_type) {
  // MinIO Application layer
  case 110:
    return "MINIO_OBJECT_PUT";
  case 111:
    return "MINIO_OBJECT_GET";
  case 112:
    return "MINIO_ERASURE_ENCODE";
  case 113:
    return "MINIO_ERASURE_DECODE";
  case 114:
    return "MINIO_XL_META";
  case 115:
    return "MINIO_REPLICATION";

  // OS layer
  case 303:
    return "OS_VFS_READ";
  case 304:
    return "OS_VFS_WRITE";

  // Filesystem layer
  case 401:
    return "FS_SYNC";

  // Device layer
  case 501:
    return "DEV_BIO_SUBMIT";
  case 502:
    return "DEV_BIO_COMPLETE";

  default:
    return "UNKNOWN";
  }
}

static struct request_flow *find_or_create_request(__u64 request_id) {
  // First, search existing requests
  for (int i = 0; i < request_count; i++) {
    if (requests[i].request_id == request_id) {
      return &requests[i];
    }
  }

  // Create new request if not found
  if (request_count < MAX_REQUESTS) {
    struct request_flow *req = &requests[request_count++];
    memset(req, 0, sizeof(*req));
    req->request_id = request_id;
    req->start_time = 0;
    return req;
  }

  return NULL;
}

static void update_request_flow(const struct multilayer_io_event *e) {
  struct request_flow *req = find_or_create_request(e->request_id);
  if (!req)
    return;

  // Update parent relationship
  if (e->parent_request_id && !req->parent_request_id) {
    req->parent_request_id = e->parent_request_id;
  }

  // Update timestamps
  if (req->start_time == 0 || e->timestamp < req->start_time) {
    req->start_time = e->timestamp;
  }
  if (e->timestamp > req->end_time) {
    req->end_time = e->timestamp;
  }

  // Update branch information
  if (e->branch_count > req->total_branches) {
    req->total_branches = e->branch_count;
  }

  // Update layer-specific metrics
  switch (e->layer) {
  case LAYER_APPLICATION:
    req->app_bytes += e->size;
    if (e->event_type == 110)
      req->op_type = 1; // PUT
    if (e->event_type == 111)
      req->op_type = 0; // GET
    if (e->filename[0] && !req->object_name[0]) {
      strncpy(req->object_name, e->filename, MAX_FILENAME_LEN - 1);
    }
    break;

  case LAYER_STORAGE_SERVICE:
    req->storage_bytes += e->size;
    if (e->is_metadata)
      req->metadata_ops++;
    if (e->is_erasure)
      req->erasure_branches++;
    if (e->replication_count > 0)
      req->replication_factor = e->replication_count;
    break;

  case LAYER_OPERATING_SYSTEM:
    req->os_bytes += e->aligned_size ? e->aligned_size : e->size;
    if (e->event_type == 303)
      req->vfs_reads++;
    if (e->event_type == 304)
      req->vfs_writes++;
    break;

  case LAYER_FILESYSTEM:
    req->fs_bytes += e->size;
    if (e->is_journal)
      req->journal_ops++;
    break;

  case LAYER_DEVICE:
    req->device_bytes += e->size;
    if (e->event_type == 501)
      req->bio_submits++;
    break;
  }
}

static void print_branch_indicator(__u32 branch_id, __u32 branch_count,
                                   __u64 parent_request_id) {
  if (!env.show_branches)
    return;

  if (parent_request_id != 0) {
    fprintf(output_fp, " [CHILD of %08llx]", parent_request_id & 0xFFFFFFFF);
  }

  if (branch_count > 1) {
    fprintf(output_fp, " [BRANCH %u/%u]", branch_id, branch_count);
  }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct multilayer_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Update request flow tracking
  if (env.correlation_mode) {
    update_request_flow(e);
  }

  t = e->timestamp / 1000000000;
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  // Format the output with request correlation
  fprintf(output_fp, "%s.%03llu %-12s %-28s %8llu %8llu %8.2f %-15s", ts,
          (e->timestamp % 1000000000) / 1000000, layer_names[e->layer],
          get_event_name(e->event_type), e->size,
          e->aligned_size ? e->aligned_size : e->size, e->latency_ns / 1000.0,
          e->comm);

  // Add flags
  if (e->is_metadata)
    fprintf(output_fp, " [META]");
  if (e->is_journal)
    fprintf(output_fp, " [JRNL]");
  if (e->is_erasure)
    fprintf(output_fp, " [ERASURE]");
  if (env.minio_only)
    fprintf(output_fp, " [MINIO]");

  // Show request correlation info
  if (env.correlation_mode) {
    fprintf(output_fp, " [REQ:%08llx]", e->request_id & 0xFFFFFFFF);
    print_branch_indicator(e->branch_id, e->branch_count, e->parent_request_id);
  }

  // Add filename for metadata operations
  if (e->filename[0] && e->is_metadata) {
    fprintf(output_fp, "\n    └─> File: %s", e->filename);
  }

  fprintf(output_fp, "\n");

  // For completed device I/O, check if request is complete
  if (e->event_type == 502 && e->layer == LAYER_DEVICE) { // DEV_BIO_COMPLETE
    struct request_flow *req = find_or_create_request(e->request_id);
    if (req) {
      req->completed_branches++;
    }
  }

  fflush(output_fp);
  return 0;
}

static void print_header() {
  fprintf(output_fp, "Multi-layer I/O tracer started!\n");
  fprintf(
      output_fp,
      "Tracing layers: Application, Storage Service, OS, Filesystem, Device\n");
  if (env.minio_only) {
    fprintf(output_fp, "MinIO-only mode enabled\n");
  }
  if (env.correlation_mode) {
    fprintf(output_fp, "Request correlation mode enabled\n");
  }

  if (env.minio_only) {
    fprintf(output_fp, "MinIO tracing configured:\n");
    fprintf(output_fp, "  Mode: Name\n");
    fprintf(output_fp, "  Trace Erasure: Yes\n");
    fprintf(output_fp, "  Trace Metadata: Yes\n");
  }

  fprintf(output_fp, "%-16s %-12s %-28s %8s %8s %8s %-15s %s\n", "TIME",
          "LAYER", "EVENT", "SIZE", "ALIGNED", "LAT(μs)", "COMM", "FLAGS");
  fprintf(output_fp, "========================================================="
                     "===============\n");

  if (env.minio_only) {
    fprintf(output_fp, ">>> TRACING MINIO PROCESSES ONLY <<<\n");
    fprintf(output_fp, "======================================================="
                       "=================\n");
  }
}

static void print_request_summary() {
  if (!env.correlation_mode || request_count == 0) {
    return;
  }

  fprintf(output_fp, "\n======================================================="
                     "=================\n");
  fprintf(output_fp, "                        REQUEST FLOW ANALYSIS\n");
  fprintf(output_fp, "========================================================="
                     "===============\n\n");

  fprintf(output_fp, "Total requests tracked: %d\n\n", request_count);

  // Sort requests by start time (simple bubble sort for small dataset)
  for (int i = 0; i < request_count - 1; i++) {
    for (int j = 0; j < request_count - i - 1; j++) {
      if (requests[j].start_time > requests[j + 1].start_time) {
        struct request_flow temp = requests[j];
        requests[j] = requests[j + 1];
        requests[j + 1] = temp;
      }
    }
  }

  // Print detailed request flow
  fprintf(output_fp, "REQUEST FLOWS (Chronological):\n");
  fprintf(output_fp, "%-12s %-8s %-32s %-10s %-10s %-10s %-10s\n", "REQUEST_ID",
          "TYPE", "OBJECT", "APP_BYTES", "OS_BYTES", "DEVICE_BYTES", "AMPLIF");
  fprintf(output_fp, "---------------------------------------------------------"
                     "---------------\n");

  for (int i = 0; i < request_count && i < 50;
       i++) { // Limit to 50 for readability
    struct request_flow *req = &requests[i];

    double amplification = 0;
    if (req->app_bytes > 0) {
      __u64 final_bytes = req->device_bytes ? req->device_bytes : req->fs_bytes;
      if (final_bytes == 0)
        final_bytes = req->os_bytes;
      amplification = (double)final_bytes / req->app_bytes;
    }

    fprintf(output_fp, "%08llx     %-8s %-32s %10llu %10llu %10llu %8.2fx\n",
            req->request_id & 0xFFFFFFFF, req->op_type ? "PUT" : "GET",
            req->object_name[0] ? req->object_name : "<unknown>",
            req->app_bytes, req->os_bytes, req->device_bytes, amplification);

    // Show branch information if applicable
    if (req->total_branches > 1) {
      fprintf(output_fp, "  └─> Branches: %u total, %u completed | ",
              req->total_branches, req->completed_branches);
      fprintf(output_fp, "VFS: %u reads, %u writes | BIO: %u submits | ",
              req->vfs_reads, req->vfs_writes, req->bio_submits);
      fprintf(output_fp, "Metadata: %u ops | Journal: %u ops\n",
              req->metadata_ops, req->journal_ops);
    }

    // Show parent-child relationships
    if (req->parent_request_id != 0) {
      fprintf(output_fp, "  └─> Parent request: %08llx\n",
              req->parent_request_id & 0xFFFFFFFF);
    }

    // Show erasure coding info if present
    if (req->erasure_branches > 0) {
      fprintf(output_fp, "  └─> Erasure coding: %u branches\n",
              req->erasure_branches);
    }
  }

  // Print aggregate statistics
  fprintf(output_fp, "\n======================================================="
                     "=================\n");
  fprintf(output_fp, "                        AGGREGATE STATISTICS\n");
  fprintf(output_fp, "========================================================="
                     "===============\n\n");

  __u64 total_app_bytes = 0;
  __u64 total_os_bytes = 0;
  __u64 total_device_bytes = 0;
  __u32 total_gets = 0;
  __u32 total_puts = 0;
  __u32 total_branched_requests = 0;

  for (int i = 0; i < request_count; i++) {
    total_app_bytes += requests[i].app_bytes;
    total_os_bytes += requests[i].os_bytes;
    total_device_bytes += requests[i].device_bytes;

    if (requests[i].op_type == 0)
      total_gets++;
    else
      total_puts++;

    if (requests[i].total_branches > 1)
      total_branched_requests++;
  }

  fprintf(output_fp, "Operation Summary:\n");
  fprintf(output_fp, "  Total GET operations:  %u\n", total_gets);
  fprintf(output_fp, "  Total PUT operations:  %u\n", total_puts);
  fprintf(output_fp, "  Branched requests:     %u (%.1f%%)\n",
          total_branched_requests,
          request_count > 0 ? (100.0 * total_branched_requests / request_count)
                            : 0);

  fprintf(output_fp, "\nI/O Amplification:\n");
  fprintf(output_fp, "  Application layer:     %llu bytes\n", total_app_bytes);
  fprintf(output_fp, "  OS layer:             %llu bytes (%.2fx)\n",
          total_os_bytes,
          total_app_bytes > 0 ? (double)total_os_bytes / total_app_bytes : 0);
  fprintf(output_fp, "  Device layer:         %llu bytes (%.2fx)\n",
          total_device_bytes,
          total_app_bytes > 0 ? (double)total_device_bytes / total_app_bytes
                              : 0);

  if (total_app_bytes > 0 && total_device_bytes > 0) {
    fprintf(output_fp, "\n*** TOTAL AMPLIFICATION: %.2fx ***\n",
            (double)total_device_bytes / total_app_bytes);
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
  struct minio_tracer_bpf *skel;
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

  skel = minio_tracer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = minio_tracer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = minio_tracer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
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
      break;
    }
  }

  // Print summary before exit
  print_request_summary();

cleanup:
  if (rb)
    ring_buffer__free(rb);
  if (skel)
    minio_tracer_bpf__destroy(skel);

  if (output_fp && output_fp != stdout) {
    fflush(output_fp);
    fclose(output_fp);
  }

  return err < 0 ? -err : 0;
}
