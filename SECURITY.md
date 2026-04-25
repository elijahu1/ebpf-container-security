# Security Policy

## ⚠️ Important Notice

This project operates at the Linux kernel level using eBPF.

It is **experimental software** and may cause:

- System instability
- Kernel panics
- Unexpected system behavior
- Elevated privilege exposure during execution

Do NOT run this on production systems.

VMs or isolated test environments are strongly recommended.

---

## Supported Versions

Only the latest development version of this repository is actively maintained.

Older versions may contain:
- Unsafe BPF programs
- Unpatched logic flaws
- Broken detection behavior

---

## Security Scope

This project focuses on:

- Kernel syscall monitoring via eBPF
- Container escape detection research
- Privilege escalation pattern observation

Out of scope:

- Network intrusion detection
- Malware analysis
- File integrity monitoring
- Host hardening recommendations

---

## Reporting a Vulnerability

If you discover a security issue, please report it responsibly.

Do NOT open a public GitHub issue for security vulnerabilities.

Instead, contact:

📧 hi@elijahu.me

Include:
- Description of the issue
- Steps to reproduce
- Kernel version and environment details
- Any logs or crash outputs

---

## Response Process

- Acknowledgement within reasonable time
- Investigation of kernel-level impact
- Fix or mitigation in a future release
- Credit provided if desired (optional)

---

## Safe Usage Guidelines

To reduce risk:

- Run inside virtual machines (recommended)
- Use non-production kernels
- Avoid running alongside critical workloads
- Monitor system logs during execution

---

## Disclosure Policy

Security issues are handled privately until a fix is available.

Coordinated disclosure is preferred.

---

## Legal Note

This software is provided as-is with no warranties.

Use at your own risk.
