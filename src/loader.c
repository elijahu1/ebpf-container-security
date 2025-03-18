#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <time.h>
#include <stdint.h>  // Fixed include

static volatile bool running = true;
static FILE *log_file = NULL;

struct event {
    char comm[16];
    char pcomm[16];
    uint32_t pid;  // Fixed type
};

void log_message(const char *message) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec, message);
    fflush(log_file);
}

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "ALERT: %s (PID: %d) spawned by %s",
             e->comm, e->pid, e->pcomm);
    log_message(log_msg);
    return 0;
}

void handle_signal(int sig) {
    running = false;
    if (log_file) fclose(log_file);
}

int main() {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    int err;

    log_file = fopen("/var/log/ebpf-container-security.log", "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        return 1;
    }

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    obj = bpf_object__open("detector.bpf.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(-errno));
        goto cleanup;
    }

    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"), 
                         handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    printf("Monitoring container escapes... (Ctrl+C to exit)\n");
    
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
