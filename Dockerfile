# Dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    clang-14 \
    llvm-14 \
    libbpf-dev \
    bpftool \
    linux-headers-6.8.0-1021-aws \
    kmod \
    git \
    make

# Set working environment
WORKDIR /app
ENV PATH="/usr/lib/llvm-14/bin:${PATH}"

# Clone repo (or use bind mount)
CMD ["bash"]
