# Makefile
CC := clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include/$(ARCH)-linux-gnu
USER_CFLAGS := -Wall -O2 -lbpf -lelf -lz

.PHONY: all build test clean

all: build

build: bin/loader

bin/loader: src/loader.c src/detector.skel.h
	@mkdir -p bin
	$(CC) $(USER_CFLAGS) -o $@ $<

src/detector.skel.h: src/detector.bpf.o
	bpftool gen skeleton $< > $@

src/detector.bpf.o: src/detector.bpf.c vmlinux.h
	$(CC) $(BPF_CFLAGS) -c $< -o $@

test: build
	sudo ./bin/loader &
	sleep 1
	sudo chmod +x examples/test-container-escape.sh
	sudo -E ./examples/test-container-escape.sh
	pkill -f bin/loader

clean:
	rm -rf src/*.o src/*.skel.h bin/
	rm -f vmlinux.h

# Optional: Generate vmlinux.h if needed
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
