#include <stdio.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>  

static volatile bool running = true;

void handle_signal(int sig) { running = false; }

int main() {
    struct bpf_object *obj = bpf_object__open("src/detector.bpf.o");
    struct bpf_program *prog;
    
    signal(SIGINT, handle_signal);
    bpf_object__load(obj);
    
    // Get and attach the program
    prog = bpf_object__find_program_by_name(obj, "detect_container_escape");
    bpf_program__attach(prog);  // <<< THIS WAS MISSING
    
    printf("Monitoring...\n");
    while(running) sleep(1);
    bpf_object__close(obj);
    return 0;
}

    struct bpf_object *obj = bpf_object__open("src/detector.bpf.o");
    signal(SIGINT, handle_signal);
    
    bpf_object__load(obj);
    printf("Monitoring container escapes...\n");
    
