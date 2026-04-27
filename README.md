# eBPF Container Security Monitor

A low-level **eBPF-based container security research tool** designed to observe syscall behavior and detect container escape patterns at the Linux kernel level.

⚠️ **Experimental Project — Not production ready**

This project is intended for research, learning, and security experimentation only.

---

## Overview

This tool uses eBPF to monitor kernel-level events and syscall activity inside containerized environments. It detects and automatically responds to:

- Container escape attempts
- Suspicious shell spawns inside containers
- Privilege escalation tools (sudo, su, chroot)
- Namespace escape tools (unshare, nsenter)

It is not a hardened detection system and should not be used in production environments.

---

## How It Works

The tool has two components:

**detector.bpf.c** — kernel-space eBPF program that attaches to the `sys_enter_execve` tracepoint. On every process execution it:
1. Asks the kernel directly whether the process lives inside a container by reading its cgroup path
2. If confirmed as a container process, checks whether the command matches known suspicious patterns
3. If suspicious, drops an event into a ring buffer

**loader.c** — userspace program that loads the eBPF program via the skeleton API, reads events off the ring buffer, prints alerts, and automatically kills the offending container via Docker.

---

## Current Status

- ✅ eBPF program loads successfully
- ✅ Kernel-confirmed container detection via cgroup path
- ✅ Suspicious syscall pattern detection
- ✅ Automated container kill response
- ⚠️ Detection rules are hardcoded (YAML rules map planned)
- ⚠️ Single runtime support (Docker only)
- ❌ Not production safe

---

## Requirements

- Ubuntu 22.04+
- Linux kernel 6.8+
- clang ≥ 14
- libbpf ≥ 1.3 (build from source — see below)
- bpftool
- Docker

---

## Installation

Clone the repository:

```bash
git clone https://github.com/elijahu1/ebpf-container-security.git
cd ebpf-container-security
```

### Build libbpf 1.3 from source

The distro libbpf (0.5.0) is too old for kernel 6.8. Build it fresh:

```bash
sudo apt-get install -y libelf-dev zlib1g-dev pkg-config
git clone https://github.com/libbpf/libbpf.git
cd libbpf && git checkout v1.3.0 && cd src
make && sudo make install LIBDIR=/usr/lib/x86_64-linux-gnu
sudo ldconfig
cd -
```

### Install build dependencies

```bash
sudo apt-get install -y \
  clang llvm libelf-dev \
  linux-tools-common linux-tools-generic \
  build-essential git docker.io
```

### Build

```bash
make build
```

---

## Usage

### Start the monitor

```bash
sudo ./bin/loader
```

Output:
Wire guy is in. Watching for container escapes...
TIME                   PID      COMM         CGROUP


### Trigger a test

```bash
sudo docker run --rm ubuntu bash -c "sleep 10 && bash"
```

Expected response:
[2026-04-27 12:15:34] ALERT pid=5118   comm=bash   cgroup=docker-e44e214e8441...
[RESPONSE] Killing container: e44e214e8441...

---

## Suspicious Patterns Detected

| Command | Reason |
|---------|--------|
| `bash`, `sh`, `zsh` | Shell spawn inside container |
| `unshare` | Namespace escape attempt |
| `nsenter` | Namespace entry attempt |
| `sudo`, `su` | Privilege escalation |
| `chroot` | Filesystem escape attempt |

---

## Roadmap

- [ ] YAML rules map — user-defined suspicious patterns
- [ ] Multi-runtime support (podman, containerd)
- [ ] Webhook alerting integration
- [ ] Pause instead of kill (preserve forensic state)
- [ ] Production hardening and safety layer

---

## Limitations

- Requires Linux kernel ≥ 6.8
- Docker only (containerd/podman support planned)
- Detection rules hardcoded in kernel program
- Not stable for production workloads
- Direct kernel interaction may cause system instability

---

## Troubleshooting

Check kernel version:
```bash
uname -r
```

List loaded BPF programs:
```bash
sudo bpftool prog list
```

Verify BTF is available:
```bash
ls /sys/kernel/btf/vmlinux
```

---

## License

This project is licensed under the **GNU Affero General Public License v3.0**.

See the `LICENSE` file for full details.

---

## Contributing

Contributions are welcome. Please see `CONTRIBUTING.md` for guidelines.

---

## Warning

This project operates at the Linux kernel level.
Improper usage may cause system instability or kernel crashes.
Use only in controlled environments (VMs recommended).
