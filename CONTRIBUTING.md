
# Contributing Guide

Thank you for your interest in contributing to this eBPF Container Security project.

This is a **low-level kernel security research tool**, so contributions must prioritize stability, clarity, and safety.

---

## ⚠️ Before You Start

This project interacts directly with the Linux kernel via eBPF.

That means:

- Bugs can crash systems
- Incorrect BPF logic may destabilize the kernel
- Testing should be done in isolated environments (VMs recommended)

Do not test on production systems.

---

## How to Contribute

### 1. Fork the Repository

Click **Fork** on GitHub to create your own copy.

---

### 2. Clone Your Fork

```bash id="ckf7q1"
git clone https://github.com/<your-username>/ebpf-container-security.git
cd ebpf-container-security
