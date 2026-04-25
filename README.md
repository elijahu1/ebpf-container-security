
---

````markdown
# eBPF Container Security Monitor

A low-level **eBPF-based container security research tool** designed to observe syscall behavior and detect potential container escape patterns at the Linux kernel level.

⚠️ **Experimental Project — Not production ready**

This project is intended for research, learning, and security experimentation only.

---

## Overview

This tool uses eBPF to monitor kernel-level events and syscall activity inside containerized environments. It aims to detect early indicators of:

- Container escape attempts
- Privilege escalation behavior
- Suspicious syscall patterns
- Runtime anomalies at kernel level

It is not a hardened detection system and should not be used in production environments.

---

## Current Status

- ✅ eBPF program loads successfully
- ✅ Syscall tracing pipeline functional
- ⚠️ Detection logic is experimental
- ⚠️ Alerting system is incomplete
- ❌ Not production safe

---

## Requirements

- Ubuntu 22.04+
- Linux kernel 6.8+
- clang ≥ 14
- libbpf-dev
- bpftool
- Docker (optional for testing)

---

## Installation

Clone the repository:

```bash
git clone https://github.com/elijahu1/ebpf-container-security.git
cd ebpf-container-security
````

Build the project:

```bash
make build
```

---

## Usage

### Start the eBPF monitor

```bash
sudo ./bin/loader
```

---

### View kernel trace output

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

### Trigger test workload

```bash
docker run --rm ubuntu unshare --user
```

---

## Docker Development Environment

Build the dev image:

```bash
docker build -t ebpf-monitor-dev .
```

Run container with kernel access:

```bash
docker run -it --rm \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v $(pwd):/app \
  ebpf-monitor-dev
```

Inside container:

```bash
make build
sudo ./bin/loader
```

---

## Limitations

* Requires Linux kernel ≥ 6.8
* Depends on host kernel headers
* Not stable for production workloads
* Detection logic is still under development
* Direct kernel interaction may cause system instability

---

## Roadmap

* Container escape detection heuristics
* Runtime anomaly scoring engine
* Alerting system (logs + webhook integration)
* Container runtime integrations (Docker / containerd)
* Production hardening and safety layer

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

Enable tracing if empty output:

```bash
echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
```

---

## License

This project is licensed under the **GNU General Public License v3.0**.

See the `LICENSE` file for full details.

---

## Contributing

Contributions are welcome. Please see `CONTRIBUTING.md` for guidelines.

---

## Warning

This project operates at the Linux kernel level.

Improper usage may cause system instability or kernel crashes.
Use only in controlled environments (VMs recommended).

```


