// detector.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

// Helper for safe string comparison
static inline __always_inline
int bpf_strncmp(const char *s1, unsigned int n, const char *s2)
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
    bpf_printk("PROCESS: %s (PID: %d) -> PARENT: %s", comm, pid, pcomm);

       if (bpf_strncmp(comm, 7, "unshare") == 0) {
        bpf_printk("ALERT: unshare executed by parent %s (PID: %d)", pcomm, pid);
    }

    // Container escape detection logic
    if (bpf_strncmp(pcomm, 6, "conta") == 0 ||    // containerd
        bpf_strncmp(pcomm, 3, "run") == 0) {      // runc/runtime
        
        // Suspicious child processes
        if (bpf_strncmp(comm, 7, "unshare") == 0 ||
            bpf_strncmp(comm, 6, "nsenter") == 0 ||
            bpf_strncmp(comm, 3, "sh") == 0 ||
            bpf_strncmp(comm, 4, "bash") == 0) {
            
            bpf_printk("ALERT: Container escape attempt detected!");
            bpf_printk("SUSPICIOUS EXEC: %s (PID: %d) spawned by %s", 
                      comm, pid, pcomm);
        }
    }

    return 0;
}

