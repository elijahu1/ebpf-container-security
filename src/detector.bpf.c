#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";
SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Detect container runtime components
    if ((comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n') ||  // containerd
        (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n')) {  // runc
        bpf_printk("ALERT: Container escape via %s", comm);
    }
    return 0;
}


