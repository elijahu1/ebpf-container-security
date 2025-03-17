#include "vmlinux.h"  // Use generated kernel headers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct pt_regs *ctx) {
    char comm[16], pcomm[16];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Get current process name
    bpf_get_current_comm(&comm, sizeof(comm));

    // Get parent process name safely
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel_str(pcomm, sizeof(pcomm), parent->comm);

    // Detection logic
    if ((pcomm[0] == 'c' && pcomm[1] == 'o' && pcomm[2] == 'n') ||  // containerd
        (pcomm[0] == 'r' && pcomm[1] == 'u' && pcomm[2] == 'n')) {  // runc
        if (comm[0] == 'u' && comm[1] == 'n' && comm[2] == 's') {   // unshare
            bpf_printk("ALERT: Container escape via %s (parent: %s)", comm, pcomm);
        }
    }
    
    return 0;
}
