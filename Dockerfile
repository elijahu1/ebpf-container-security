FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    git \
    sudo

WORKDIR /app
COPY . .
