#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct trace_event_raw_sys_enter *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug: Print all execve calls
    bpf_printk("EXECVE: %s", comm);
    
    // Detect container escape patterns
    if (bpf_strstr(comm, "docker") || 
        bpf_strstr(comm, "containerd") ||
        bpf_strstr(comm, "runc")) {
        bpf_printk("Container escape detected: %s", comm);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
