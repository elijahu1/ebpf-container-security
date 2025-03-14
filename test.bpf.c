cat <<EOF > test.bpf.c
#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(void *ctx) {
    char msg[] = "Hello from eBPF!";
    bpf_printk("%s", msg);
    return 0;
}

char _license[] SEC("license") = "GPL";
EOF
