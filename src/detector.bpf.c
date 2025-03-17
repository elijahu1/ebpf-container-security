// detector.bpf.c (fixed)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

// Renamed function
static __always_inline
int custom_strncmp(const char *s1, unsigned int n, const char *s2)
{
    for (unsigned int i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return -1;
        if (s1[i] == 0)
            return 0;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct trace_event_raw_sys_enter *ctx)
{
    char comm[TASK_COMM_LEN] = {0};
    char pcomm[TASK_COMM_LEN] = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Get current process name
    bpf_get_current_comm(&comm, sizeof(comm));

    // Safely get parent task
    if (BPF_CORE_READ(task, real_parent)) {
        BPF_CORE_READ_INTO(&parent, task, real_parent);
    }
    if (!parent)
        return 0;

    // Get parent process name
    bpf_probe_read_kernel_str(&pcomm, sizeof(pcomm), parent->comm);

    // Debug: Print all process spawns
    bpf_printk("DEBUG: Process '%s' (PID: %d) spawned by '%s'", comm, pid, pcomm);

    // Container escape detection logic (updated function name)
    if (custom_strncmp(pcomm, 15, "containerd-shim") == 0 ||
       custom_strncmp(pcomm, 9, "containerd") == 0 ||
       custom_strncmp(pcomm, 3, "ctr") == 0 ||
       custom_strncmp(pcomm, 3, "run") == 0) {
        
        if (custom_strncmp(comm, 7, "unshare") == 0 ||
            custom_strncmp(comm, 6, "nsenter") == 0 ||
            custom_strncmp(comm, 3, "sh") == 0 ||
            custom_strncmp(comm, 4, "bash") == 0) {
            
            bpf_printk("ALERT: Container escape detected!");
            bpf_printk("DETAILS: %s (PID: %d) spawned by %s", comm, pid, pcomm);
        }
    }

    return 0;
}
