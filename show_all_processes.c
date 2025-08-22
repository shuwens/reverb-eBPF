// Show All Processes Tracer - Userspace program
// File: show_all_processes.c

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "show_all_processes.skel.h"

#define MAX_COMM_LEN 16

struct process_event {
  __u64 timestamp;
  __u32 pid;
  __u64 size;
  __s32 retval;
  char comm[MAX_COMM_LEN];
};

static volatile bool exiting = false;
static int event_count = 0;

static void sig_handler(int sig) { exiting = true; }

static int bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

// Helper function to test our detection logic in userspace
static const char *test_detection(const char *comm) {
  // Same logic as eBPF version
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    char c1 = comm[i];
    char c2 = comm[i + 1];
    char c3 = comm[i + 2];
    char c4 = comm[i + 3];

    if (c1 == 'm' && c2 == 'i' && c3 == 'n' && c4 == 'i')
      return "MinIO";
    if (c1 == 'c' && c2 == 'e' && c3 == 'p' && c4 == 'h')
      return "Ceph";
    if (c1 == 'e' && c2 == 't' && c3 == 'c' && c4 == 'd')
      return "etcd";
    if (c1 == 'p' && c2 == 'o' && c3 == 's' && c4 == 't')
      return "PostgreSQL";
    if (c1 == 'g' && c2 == 'l' && c3 == 'u' && c4 == 's')
      return "GlusterFS";
  }
  return "Unknown";
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct process_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  event_count++;

  // Convert timestamp to readable format
  t = e->timestamp / 1000000000;
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  // Test our detection logic
  const char *detected = test_detection(e->comm);

  printf("%s.%03llu %-8u %-15s %-8llu %-10s %d\n", ts,
         (e->timestamp % 1000000000) / 1000000, e->pid, e->comm, e->size,
         detected, e->retval);

  fflush(stdout);
  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct show_all_processes_bpf *skel;
  int err;
  int duration = 10;

  if (argc > 1) {
    duration = atoi(argv[1]);
    if (duration <= 0)
      duration = 10;
  }

  printf("Show All Processes Tracer - Debug process name detection\n");
  printf("Duration: %d seconds\n", duration);
  printf("This will show ALL write syscalls with detection results\n\n");

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  if (bump_memlock_rlimit()) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    return 1;
  }

  skel = show_all_processes_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = show_all_processes_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = show_all_processes_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("%-17s %-8s %-15s %-8s %-10s %s\n", "TIME", "PID", "COMM", "SIZE",
         "DETECTED", "RET");
  printf("====================================================================="
         "===========\n");

  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  time_t start_time = time(NULL);
  while (!exiting) {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling ring buffer: %d\n", err);
      break;
    }

    if ((time(NULL) - start_time) >= duration) {
      printf("\nTracing completed after %d seconds\n", duration);
      break;
    }
  }

  printf("Total events captured: %d\n", event_count);

cleanup:
  ring_buffer__free(rb);
  show_all_processes_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
