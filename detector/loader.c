#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>

static volatile bool running = true;

void sig_handler(int sig) {
    running = false;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. Load BPF object
    obj = bpf_object__open("escape_detector.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // 2. Load & Verify
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    // 3. Attach to Tracepoint
    prog = bpf_object__find_program_by_name(obj, "detect_container_escape");
    link = bpf_program__attach(prog);  // Corrected: assign to link pointer
    if (!link) {
        fprintf(stderr, "Failed to attach program\n");
        goto cleanup;
    }

    printf("Detector active. Press Ctrl+C to exit.\n");
    while (running) {
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
