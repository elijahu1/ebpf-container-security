#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Detect container-related processes
    if (comm[0] == 'd' && comm[1] == 'o' && comm[2] == 'c') {
        bpf_printk("Container escape attempt: %s", comm);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
