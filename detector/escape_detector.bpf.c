#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "bpf_helpers.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct syscall_execve_args *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Basic container escape detection
    if (comm[0] == 'd' && comm[1] == 'o' && comm[2] == 'c' && comm[3] == 'k') {
        bpf_printk("Container escape attempt detected: %s", comm);
    }
    return 0;
}
