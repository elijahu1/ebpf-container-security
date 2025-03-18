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
[TAB]$(CC) $(USER_CFLAGS) -o $@ $<

$(SKEL_H): $(BPF_OBJ)
[TAB]bpftool gen skeleton $< > $@

$(BPF_OBJ): $(SRC_DIR)/detector.bpf.c vmlinux.h
[TAB]$(CC) $(BPF_CFLAGS) -c $< -o $@

$(BIN_DIR):
[TAB]@mkdir -p $@

### Test Rule ###
test: build
[TAB]@sudo $(LOADER) &
[TAB]@sleep 1
[TAB]@sudo -E ./examples/test-container-escape.sh || true
[TAB]@pkill -f $(LOADER)

### Clean Rule ###
clean:
[TAB]@rm -rf $(SRC_DIR)/*.o $(SRC_DIR)/*.skel.h $(BIN_DIR)
[TAB]@rm -f vmlinux.h

### vmlinux.h Generation ###
vmlinux.h:
[TAB]@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

### Log Rotation Rules ###
install-logrotate:
[TAB]@echo "🔧 Installing logrotate configuration..."
[TAB]@sudo bash -c 'tee /etc/logrotate.d/ebpf-container-security > /dev/null <<EOF
/var/log/ebpf-container-security.log {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    create 0644 root root
}
EOF'
[TAB]@sudo logrotate --force /etc/logrotate.d/ebpf-container-security
[TAB]@echo "✅ Log rotation configured"

uninstall-logrotate:
[TAB]@echo "🧹 Removing logrotate configuration..."
[TAB]@sudo rm -f /etc/logrotate.d/ebpf-container-security
[TAB]@echo "🗑️ Log rotation removed"
