### Makefile ###
CC := clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include/$(ARCH)-linux-gnu
USER_CFLAGS := -Wall -O2 -lbpf -lelf -lz

### Directories ###
SRC_DIR := src
BIN_DIR := bin

### File Targets ###
BPF_OBJ := $(SRC_DIR)/detector.bpf.o
SKEL_H := $(SRC_DIR)/detector.skel.h
LOADER := $(BIN_DIR)/loader

### Phony Targets ###
.PHONY: all build test clean install-logrotate uninstall-logrotate

### Main Targets ###
all: build install-logrotate

build: $(LOADER)

### Build Rules (TABS REQUIRED BELOW) ###
$(LOADER): $(SRC_DIR)/loader.c $(SKEL_H) | $(BIN_DIR)
	$(CC) $(USER_CFLAGS) -o $@ $<

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BPF_OBJ): $(SRC_DIR)/detector.bpf.c vmlinux.h
	$(CC) $(BPF_CFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $@

### Test Rule ###
test: build
	@sudo $(LOADER) &
	@sleep 1
	@sudo -E ./examples/test-container-escape.sh || true
	@pkill -f $(LOADER)

### Clean Rule ###
clean:
	@rm -rf $(SRC_DIR)/*.o $(SRC_DIR)/*.skel.h $(BIN_DIR)
	@rm -f vmlinux.h

### vmlinux.h Generation ###
vmlinux.h:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

install-logrotate:
	./setup-logrotate.sh

