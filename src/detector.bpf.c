#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

/* ── Mailbox ── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ── Note the wire guy drops ── */
struct event {
    char comm[16];
    char cgroup[64];
    u32  pid;
};

/* ── Step 1: Ask the Principal — is this guy from a container? ──
 * Reads the cgroup name from the kernel's own ledger.
 * Container cgroups contain "docker", "kubepods", or "containerd".
 * Host processes never do. Can't be faked. */
static __always_inline
int is_container(struct task_struct *task)
{
    char cgrp_name[64] = {0};

    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn)
        return 0;

    bpf_probe_read_kernel_str(cgrp_name, sizeof(cgrp_name),
                              BPF_CORE_READ(kn, name));

    /* check for docker/<id> */
    for (int i = 0; i < 56; i++) {
        if (cgrp_name[i] == 'd' &&
            cgrp_name[i+1] == 'o' &&
            cgrp_name[i+2] == 'c' &&
            cgrp_name[i+3] == 'k' &&
            cgrp_name[i+4] == 'e' &&
            cgrp_name[i+5] == 'r') return 1;

        if (cgrp_name[i] == 'k' &&
            cgrp_name[i+1] == 'u' &&
            cgrp_name[i+2] == 'b' &&
            cgrp_name[i+3] == 'e') return 1;

        if (cgrp_name[i] == 'c' &&
            cgrp_name[i+1] == 'o' &&
            cgrp_name[i+2] == 'n' &&
            cgrp_name[i+3] == 't' &&
            cgrp_name[i+4] == 'a' &&
            cgrp_name[i+5] == 'i' &&
            cgrp_name[i+6] == 'n' &&
            cgrp_name[i+7] == 'e' &&
            cgrp_name[i+8] == 'r') return 1;

        if (cgrp_name[i] == 0) break;
    }
    return 0;
}

/* ── Step 2: Check the notes — is what he's doing sus? ──
 * Hardcoded for now. YAML rules map comes next. */
static __always_inline
int is_suspicious(const char *comm)
{
    /* shell spawns */
    if (comm[0]=='s' && comm[1]=='h' && comm[2]==0) return 1;
    if (comm[0]=='b' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h' && comm[4]==0) return 1;
    if (comm[0]=='z' && comm[1]=='s' && comm[2]=='h' && comm[3]==0) return 1;
    /* namespace escape tools */
    if (comm[0]=='u' && comm[1]=='n' && comm[2]=='s' && comm[3]=='h' &&
        comm[4]=='a' && comm[5]=='r' && comm[6]=='e') return 1;
    if (comm[0]=='n' && comm[1]=='s' && comm[2]=='e' && comm[3]=='n' &&
        comm[4]=='t' && comm[5]=='e' && comm[6]=='r') return 1;
    /* privilege escalation */
    if (comm[0]=='s' && comm[1]=='u' && comm[2]=='d' && comm[3]=='o') return 1;
    if (comm[0]=='s' && comm[1]=='u' && comm[2]==0) return 1;
    if (comm[0]=='c' && comm[1]=='h' && comm[2]=='r' && comm[3]=='o' && comm[4]=='o' && comm[5]=='t') return 1;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_container_escape(struct trace_event_raw_sys_enter *ctx)
{
    char comm[16] = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    /* ── Step 1: Ask Principal — host process? bounce immediately ── */
    if (!is_container(task)) return 0;

    /* ── Step 2: Check notes — sus? tape it ── */
    if (!is_suspicious(comm)) return 0;

    /* ── Drop intel in Mailbox ── */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memcpy(e->comm, comm, sizeof(comm));
    struct kernfs_node *kn2 = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn2) { bpf_ringbuf_discard(e, 0); return 0; }
    const char *kn_name = BPF_CORE_READ(kn2, name);
    bpf_probe_read_kernel_str(e->cgroup, sizeof(e->cgroup), kn_name);
    e->pid = pid;
    bpf_ringbuf_submit(e, 0);

    return 0;
}
