**CONTRIBUTING.md**
```markdown
# Contribution Guide

We welcome help with this early-stage project! Current priorities:

1. Improve detection logic for common escapes:
   - Namespace breakout (unshare, nsenter)
   - Mount abuse
   - Privileged container escapes

2. Reduce false positives in process tracing

3. Build reliable alerting pipeline

## Guidelines
- Open an issue before submitting PRs
- Keep BPF programs kernel 6.8+ compatible
- Use libbpf-based loading (no BCC)
- Document all detection patterns

## Development Setup
```bash
# Ubuntu 22.04+ required
make build
sudo ./bin/loader

# Test with:
make test
