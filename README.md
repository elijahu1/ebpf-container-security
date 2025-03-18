# eBPF Container Security Monitor (Early Development)

🔍 *eBPF-based container escape detection prototype | Kernel 6.8+ | Early development stage | Not production-ready*

⚠️ **Experimental Project**  
This is a work-in-progress eBPF-based container escape detection system. Currently in active development - detection logic and alerting are not fully functional yet.

## Current State
- Basic eBPF program loading works
- Syscall tracing infrastructure in place
- Detection patterns under development
- **No reliable alerts generated yet**

## Prerequisites
- Ubuntu 22.04+ (AWS EC2 tested)
- Linux kernel 6.8+
- clang 14+, libbpf-dev, bpftool

## Installation
```bash
sudo apt update && sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
git clone https://github.com/yourusername/ebpf-container-security.git
cd ebpf-container-security
make build
```

## Usage
```bash
# Load detector
sudo ./bin/loader

# In another terminal, monitor logs
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Trigger test (no alerts expected yet)
docker run --rm ubuntu unshare --user
```

## Docker Development Environment
Rebuild the exact testing environment:
```bash
# Build image (from project root)
docker build -t ebpf-monitor-dev .

# Run with host kernel headers access
docker run -it --rm \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v $(pwd):/app \
  ebpf-monitor-dev

# Inside container:
make build && sudo ./bin/loader
```

**Key Limitations**:
- Requires host kernel 6.8+
- Bind mounts needed for kernel headers
- BPF programs interact directly with host kernel

## Troubleshooting
If you get no output:
- Verify kernel version matches headers: `uname -r`
- Check BPF program load: `sudo bpftool prog list`
- Ensure tracing is enabled: `sudo sh -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'`

## Roadmap
- [ ] Basic container escape detection
- [ ] Alert filtering
- [ ] Integration with container runtimes
- [ ] Production deployment guide

## License
This project is licensed under [GNU GPLv3](LICENSE.md)

---

**Contributions welcome!** See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
```

