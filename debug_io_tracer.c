// Debug I/O Tracer - Userspace program (traces all processes)
// File: debug_io_tracer.c

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// Include the auto-generated skeleton
#include "debug_io_tracer.skel.h"

#define MAX_COMM_LEN 16

struct debug_io_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 is_read;
  __u64 size;
  __s32 retval;
  char comm[MAX_COMM_LEN];
};

static volatile bool exiting = false;
static bool verbose = false;
static int event_count = 0;

static void sig_handler(int sig) { exiting = true; }

static int bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct debug_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  event_count++;

  // Convert timestamp to readable format
  t = e->timestamp / 1000000000;
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  printf("%s.%09llu %-8u %-8u %-15s %-5s %-8llu %d\n", ts,
         e->timestamp % 1000000000, e->pid, e->tid, e->comm,
         e->is_read ? "READ" : "WRITE", e->size, e->retval);

  fflush(stdout);
  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct debug_io_tracer_bpf *skel;
  int err;
  int duration = 5; // Default 5 seconds

  if (argc > 1) {
    duration = atoi(argv[1]);
    if (duration <= 0)
      duration = 5;
  }

  if (argc > 2 && strcmp(argv[2], "-v") == 0) {
    verbose = true;
  }

  printf("Debug I/O Tracer - Tracing ALL processes for %d seconds\n", duration);
  printf("Press Ctrl+C to stop early\n\n");

  // Set up signal handlers
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // Bump RLIMIT_MEMLOCK
  if (bump_memlock_rlimit()) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    return 1;
  }

  // Load and verify BPF application
  skel = debug_io_tracer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  // Load BPF programs
  err = debug_io_tracer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  // Attach BPF programs
  err = debug_io_tracer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("Tracer attached! Monitoring syscalls...\n");
  printf("%-23s %-8s %-8s %-15s %-5s %-8s %s\n", "TIME", "PID", "TID", "COMM",
         "OP", "SIZE", "RET");
  printf("====================================================================="
         "===========\n");

  // Set up ring buffer polling
  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  // Main event loop
  time_t start_time = time(NULL);
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling ring buffer: %d\n", err);
      break;
    }

    // Check duration limit
    if ((time(NULL) - start_time) >= duration) {
      printf("\nTracing completed after %d seconds\n", duration);
      break;
    }
  }

  printf("\nSummary: Captured %d I/O events\n", event_count);

cleanup:
  ring_buffer__free(rb);
  debug_io_tracer_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
