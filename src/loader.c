#include <stdio.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>

static volatile bool running = true;

void handle_signal(int sig) { running = false; }

int main() {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;

    obj = bpf_object__open("src/detector.bpf.o");
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "detect_container_escape");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach program\n");
        goto cleanup;
    }

    printf("Monitoring... (Ctrl+C to exit)\n");
    signal(SIGINT, handle_signal);
    while(running) sleep(1);

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
