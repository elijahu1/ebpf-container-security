#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    char comm[16];
    char pcomm[16];
    u32 pid;
};

static __always_inline
int custom_strncmp(const char *s1, unsigned int n, const char *s2)
{
    for (unsigned int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) return -1;
        if (s1[i] == 0) return 0;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    char comm[TASK_COMM_LEN] = {0};
    char pcomm[TASK_COMM_LEN] = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (BPF_CORE_READ(task, real_parent)) {
        BPF_CORE_READ_INTO(&parent, task, real_parent);
    }
    if (!parent) return 0;

    bpf_probe_read_kernel_str(&pcomm, sizeof(pcomm), parent->comm);

    if (custom_strncmp(pcomm, 15, "containerd-shim") == 0 ||
       custom_strncmp(pcomm, 9, "containerd") == 0 ||
       custom_strncmp(pcomm, 3, "ctr") == 0 ||
       custom_strncmp(pcomm, 3, "run") == 0) {
        
        if (custom_strncmp(comm, 7, "unshare") == 0 ||
            custom_strncmp(comm, 6, "nsenter") == 0 ||
            custom_strncmp(comm, 3, "sh") == 0 ||
            custom_strncmp(comm, 4, "bash") == 0) {
            
            e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                __builtin_memcpy(e->comm, comm, sizeof(comm));
                __builtin_memcpy(e->pcomm, pcomm, sizeof(pcomm));
                e->pid = pid;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    return 0;
}
