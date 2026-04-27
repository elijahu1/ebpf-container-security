#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include "detector.skel.h"

static volatile bool running = true;

struct event {
    char comm[16];
    char cgroup[64];
    uint32_t pid;
};

static int handle_event(void *ctx, void *data, size_t size)
{
    struct event *e = data;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    printf("[%04d-%02d-%02d %02d:%02d:%02d] ALERT pid=%-6d comm=%-12s cgroup=%s\n",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec,
           e->pid, e->comm, e->cgroup);
    fflush(stdout);

    /* jump the rogue container -- extract ID from "docker-<full-id>" */
    const char *prefix = "docker-";
    char *cgroup = e->cgroup;
    if (strncmp(cgroup, prefix, 7) == 0) {
        /* full 64-char ID is cgroup string after "docker-" */
        char container_id[65] = {0};
        strncpy(container_id, cgroup + 7, 64);

        /* deduplicate -- skip if we already jumped this container */
        static char last_jumped[65] = {0};
        if (strncmp(last_jumped, container_id, 64) == 0) {
            return 0;
        }
        strncpy(last_jumped, container_id, 64);

        char cmd[128];
        snprintf(cmd, sizeof(cmd), "docker kill %s 2>&1", container_id);
        printf("[RESPONSE] Killing container: %.12s\n", container_id);
        fflush(stdout);
        system(cmd);
    }

    return 0;
}

void handle_signal(int sig) { running = false; }

int main()
{
    struct detector_bpf *skel = NULL;
    struct ring_buffer   *rb   = NULL;
    int err;

    /* unlock memory for BPF maps */
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    /* open + load + verify via skeleton */
    skel = detector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    /* attach wire guy to tracepoint */
    err = detector_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }

    /* hook up mailbox reader */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Wire guy is in. Watching for container escapes...\n");
    printf("%-22s %-8s %-12s %s\n", "TIME", "PID", "COMM", "CGROUP");
    printf("%-22s %-8s %-12s %s\n", "----", "---", "----", "------");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Ring buffer poll error: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    detector_bpf__destroy(skel);
    return 0;
}
