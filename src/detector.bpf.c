#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct pt_regs *ctx) {
    char comm[16], pcomm[16];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Get current and parent process names
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_kernel_str(pcomm, sizeof(pcomm), task->real_parent->comm);

    // Custom string comparison for "containerd" and "runc"
    int is_container_runtime = 0;
    
    // Check parent name (16-byte comparison)
    if ((pcomm[0] == 'c' && pcomm[1] == 'o' && pcomm[2] == 'n') ||  // containerd
        (pcomm[0] == 'r' && pcomm[1] == 'u' && pcomm[2] == 'n')) {  // runc
        is_container_runtime = 1;
    }

    // Check current process for suspicious commands
    int is_suspicious = 0;
    if ((comm[0] == 'u' && comm[1] == 'n' && comm[2] == 's') ||  // unshare
        (comm[0] == 'm' && comm[1] == 'o' && comm[2] == 'u')) {  // mount
        is_suspicious = 1;
    }

    if (is_container_runtime && is_suspicious) {
        bpf_printk("ALERT: %s spawned by %s", comm, pcomm);
    }
    
    return 0;
}
