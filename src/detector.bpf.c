#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

bpf_printk("EXECVE: %s", comm);

    // Combined check for docker and unshare
    if ((comm[0] == 'd' && comm[1] == 'o' && comm[2] == 'c') ||  // docker
        (comm[0] == 'u' && comm[1] == 'n' && comm[2] == 's')) {  // unshare
        bpf_printk("Container escape detected: %s", comm);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
