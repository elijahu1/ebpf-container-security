#include <stdio.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>  

static volatile bool running = true;

void handle_signal(int sig) { running = false; }

int main() {
    struct bpf_object *obj = bpf_object__open("src/detector.bpf.o");
    signal(SIGINT, handle_signal);
    
    bpf_object__load(obj);
    printf("Monitoring container escapes...\n");
    
    while(running) sleep(1);  
    
    bpf_object__close(obj);
    return 0;
}
