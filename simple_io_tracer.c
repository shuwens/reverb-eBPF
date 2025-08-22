// Simple I/O Tracer - Userspace program
// File: simple_io_tracer.c

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// Include the auto-generated skeleton
#include "simple_io_tracer.skel.h"

#define MAX_COMM_LEN 16

// Event types (must match kernel program)
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_VFS_READ 3
#define EVENT_TYPE_VFS_WRITE 4
#define EVENT_TYPE_BLOCK_READ 5
#define EVENT_TYPE_BLOCK_WRITE 6

// Storage system types
#define SYSTEM_TYPE_UNKNOWN 0
#define SYSTEM_TYPE_MINIO 1
#define SYSTEM_TYPE_CEPH 2
#define SYSTEM_TYPE_ETCD 3
#define SYSTEM_TYPE_POSTGRES 4
#define SYSTEM_TYPE_GLUSTER 5

struct storage_io_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 event_type;
  __u32 system_type;
  __u64 size;
  __u64 offset;
  __u64 latency_start;
  __u32 dev_major;
  __u32 dev_minor;
  __s32 retval;
  char comm[MAX_COMM_LEN];
};

// Statistics tracking
struct system_stats {
  __u64 syscall_reads;
  __u64 syscall_writes;
  __u64 vfs_reads;
  __u64 vfs_writes;
  __u64 block_reads;
  __u64 block_writes;
  __u64 total_read_bytes;
  __u64 total_write_bytes;
  __u64 total_read_latency;
  __u64 total_write_latency;
  const char *name;
};

static struct system_stats stats[6] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "Unknown"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "MinIO"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "Ceph"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "etcd"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "PostgreSQL"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "GlusterFS"}};

static struct env {
  bool verbose;
  bool json_output;
  bool realtime;
  int duration;
  const char *output_file;
} env = {
    .verbose = false,
    .json_output = false,
    .realtime = true,
    .duration = 0,
    .output_file = NULL,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"json", 'j', NULL, 0, "Output in JSON format"},
    {"duration", 'd', "DURATION", 0, "Trace for specified duration (seconds)"},
    {"output", 'o', "FILE", 0, "Output to file instead of stdout"},
    {"quiet", 'q', NULL, 0, "Disable real-time output, only show summary"},
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
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "Simple I/O tracer for storage systems using eBPF",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;

static void sig_handler(int sig) { exiting = true; }

const char *get_event_type_name(int type) {
  switch (type) {
  case EVENT_TYPE_SYSCALL_READ:
    return "SYSCALL_READ";
  case EVENT_TYPE_SYSCALL_WRITE:
    return "SYSCALL_WRITE";
  case EVENT_TYPE_VFS_READ:
    return "VFS_READ";
  case EVENT_TYPE_VFS_WRITE:
    return "VFS_WRITE";
  case EVENT_TYPE_BLOCK_READ:
    return "BLOCK_READ";
  case EVENT_TYPE_BLOCK_WRITE:
    return "BLOCK_WRITE";
  default:
    return "UNKNOWN";
  }
}

static void update_stats(const struct storage_io_event *e) {
  if (e->system_type >= 6)
    return;

  struct system_stats *s = &stats[e->system_type];

  switch (e->event_type) {
  case EVENT_TYPE_SYSCALL_READ:
    s->syscall_reads++;
    s->total_read_bytes += e->size;
    s->total_read_latency += e->latency_start;
    break;
  case EVENT_TYPE_SYSCALL_WRITE:
    s->syscall_writes++;
    s->total_write_bytes += e->size;
    s->total_write_latency += e->latency_start;
    break;
  case EVENT_TYPE_VFS_READ:
    s->vfs_reads++;
    break;
  case EVENT_TYPE_VFS_WRITE:
    s->vfs_writes++;
    break;
  case EVENT_TYPE_BLOCK_READ:
    s->block_reads++;
    break;
  case EVENT_TYPE_BLOCK_WRITE:
    s->block_writes++;
    break;
  }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct storage_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Update statistics
  update_stats(e);

  if (!env.realtime)
    return 0;

  // Convert timestamp to readable format
  t = e->timestamp / 1000000000; // Convert nanoseconds to seconds
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (env.json_output) {
    fprintf(output_fp,
            "{\"timestamp\":\"%s.%09llu\","
            "\"pid\":%u,"
            "\"tid\":%u,"
            "\"comm\":\"%s\","
            "\"system\":\"%s\","
            "\"event_type\":\"%s\","
            "\"size\":%llu,"
            "\"offset\":%llu,"
            "\"dev_major\":%u,"
            "\"dev_minor\":%u,"
            "\"latency_us\":%.2f,"
            "\"retval\":%d}\n",
            ts, e->timestamp % 1000000000, e->pid, e->tid, e->comm,
            stats[e->system_type].name, get_event_type_name(e->event_type),
            e->size, e->offset, e->dev_major, e->dev_minor,
            e->latency_start / 1000.0, // Convert to microseconds
            e->retval);
  } else {
    fprintf(output_fp,
            "%s.%09llu %-8s %-15s %-8u %-8u %-15s %-8llu %-12llu %8.2f %d\n",
            ts, e->timestamp % 1000000000, stats[e->system_type].name,
            get_event_type_name(e->event_type), e->pid, e->tid, e->comm,
            e->size, e->offset, e->latency_start / 1000.0, e->retval);
  }

  fflush(output_fp);
  return 0;
}

static void print_header() {
  if (env.json_output || !env.realtime)
    return;

  fprintf(output_fp, "%-23s %-8s %-15s %-8s %-8s %-15s %-8s %8s %s\n", "TIME",
          "SYSTEM", "EVENT_TYPE", "PID", "TID", "COMM", "SIZE", "LAT(us)",
          "RET");
  fprintf(output_fp, "%s\n",
          "===================================================================="
          "============");
}

static void print_summary() {
  if (env.json_output) {
    fprintf(output_fp, "{\"summary\":{\n");
    for (int i = 1; i < 6; i++) { // Skip UNKNOWN
      struct system_stats *s = &stats[i];
      if (s->syscall_reads + s->syscall_writes == 0)
        continue;

      // Calculate complete amplification factors
      double read_amp_total =
          s->syscall_reads > 0
              ? (double)(s->vfs_reads + s->block_reads) / s->syscall_reads
              : 0;
      double write_amp_total =
          s->syscall_writes > 0
              ? (double)(s->vfs_writes + s->block_writes) / s->syscall_writes
              : 0;
      double read_amp_vfs =
          s->syscall_reads > 0 ? (double)s->vfs_reads / s->syscall_reads : 0;
      double write_amp_vfs =
          s->syscall_writes > 0 ? (double)s->vfs_writes / s->syscall_writes : 0;

      fprintf(output_fp, "  \"%s\":{\n", s->name);
      fprintf(output_fp, "    \"syscall_reads\":%llu,\n", s->syscall_reads);
      fprintf(output_fp, "    \"syscall_writes\":%llu,\n", s->syscall_writes);
      fprintf(output_fp, "    \"vfs_reads\":%llu,\n", s->vfs_reads);
      fprintf(output_fp, "    \"vfs_writes\":%llu,\n", s->vfs_writes);
      fprintf(output_fp, "    \"block_reads\":%llu,\n", s->block_reads);
      fprintf(output_fp, "    \"block_writes\":%llu,\n", s->block_writes);
      fprintf(output_fp, "    \"read_amplification_vfs\":%.2f,\n",
              read_amp_vfs);
      fprintf(output_fp, "    \"write_amplification_vfs\":%.2f,\n",
              write_amp_vfs);
      fprintf(output_fp, "    \"read_amplification_total\":%.2f,\n",
              read_amp_total);
      fprintf(output_fp, "    \"write_amplification_total\":%.2f,\n",
              write_amp_total);
      fprintf(output_fp, "    \"total_read_bytes\":%llu,\n",
              s->total_read_bytes);
      fprintf(output_fp, "    \"total_write_bytes\":%llu\n",
              s->total_write_bytes);
      fprintf(output_fp, "  }%s\n", i < 5 ? "," : "");
    }
    fprintf(output_fp, "}}\n");
  } else {
    fprintf(output_fp, "\n=== Complete I/O Amplification Analysis ===\n");
    fprintf(output_fp, "%-12s %6s %6s %6s %6s %6s %6s %8s %8s %10s %10s\n",
            "SYSTEM", "SYS_R", "SYS_W", "VFS_R", "VFS_W", "BLK_R", "BLK_W",
            "VFS_R_AMP", "VFS_W_AMP", "TOT_R_AMP", "TOT_W_AMP");
    fprintf(output_fp, "======================================================="
                       "=========================\n");

    for (int i = 1; i < 6; i++) { // Skip UNKNOWN
      struct system_stats *s = &stats[i];
      if (s->syscall_reads + s->syscall_writes == 0)
        continue;

      double read_amp_total =
          s->syscall_reads > 0
              ? (double)(s->vfs_reads + s->block_reads) / s->syscall_reads
              : 0;
      double write_amp_total =
          s->syscall_writes > 0
              ? (double)(s->vfs_writes + s->block_writes) / s->syscall_writes
              : 0;
      double read_amp_vfs =
          s->syscall_reads > 0 ? (double)s->vfs_reads / s->syscall_reads : 0;
      double write_amp_vfs =
          s->syscall_writes > 0 ? (double)s->vfs_writes / s->syscall_writes : 0;

      fprintf(output_fp,
              "%-12s %6llu %6llu %6llu %6llu %6llu %6llu %8.2f %8.2f %10.2f "
              "%10.2f\n",
              s->name, s->syscall_reads, s->syscall_writes, s->vfs_reads,
              s->vfs_writes, s->block_reads, s->block_writes, read_amp_vfs,
              write_amp_vfs, read_amp_total, write_amp_total);
    }

    fprintf(output_fp, "\nData Transfer Summary:\n");
    for (int i = 1; i < 6; i++) {
      struct system_stats *s = &stats[i];
      if (s->total_read_bytes + s->total_write_bytes == 0)
        continue;
      fprintf(output_fp, "%-12s: Read: %llu bytes, Write: %llu bytes\n",
              s->name, s->total_read_bytes, s->total_write_bytes);
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
  struct simple_io_tracer_bpf *skel;
  int err;

  // Parse command line arguments
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  // Set up signal handlers
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // Open output file if specified
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

  // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
  if (bump_memlock_rlimit()) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    return 1;
  }

  // Load and verify BPF application
  skel = simple_io_tracer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  // Load BPF programs
  err = simple_io_tracer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  // Attach BPF programs
  err = simple_io_tracer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  if (env.verbose)
    fprintf(
        stderr,
        "Simple I/O tracer started! Tracing syscalls for storage systems.\n");

  // Set up ring buffer polling
  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  print_header();

  // Main event loop
  time_t start_time = time(NULL);
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
      break;
    }
  }

  print_summary();

cleanup:
  ring_buffer__free(rb);
  simple_io_tracer_bpf__destroy(skel);

  if (output_fp != stdout)
    fclose(output_fp);

  return err < 0 ? -err : 0;
}
