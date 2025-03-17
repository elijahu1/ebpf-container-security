# Makefile
CC := clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include/$(ARCH)-linux-gnu
USER_CFLAGS := -Wall -O2 -lbpf -lelf -lz

# Directories
SRC_DIR := src
BIN_DIR := bin

# Targets
BPF_OBJ := $(SRC_DIR)/detector.bpf.o
SKEL_H := $(SRC_DIR)/detector.skel.h
LOADER := $(BIN_DIR)/loader

.PHONY: all build test clean install-logrotate uninstall-logrotate

all: build install-logrotate

build: $(LOADER)

$(LOADER): $(SRC_DIR)/loader.c $(SKEL_H) | $(BIN_DIR)
	$(CC) $(USER_CFLAGS) -o $@ $<

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BPF_OBJ): $(SRC_DIR)/detector.bpf.c vmlinux.h
	$(CC) $(BPF_CFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $@

test: build
	@sudo $(LOADER) &
	@sleep 1
	@sudo -E ./examples/test-container-escape.sh || true
	@pkill -f $(LOADER)

clean:
	@rm -rf $(SRC_DIR)/*.o $(SRC_DIR)/*.skel.h $(BIN_DIR)
	@rm -f vmlinux.h

vmlinux.h:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

install-logrotate:
	@echo "🔧 Installing logrotate configuration..."
	@sudo bash -c 'tee /etc/logrotate.d/ebpf-container-security > /dev/null <<EOF
/var/log/ebpf-container-security.log {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    create 0644 root root
}
EOF'
	@sudo logrotate --force /etc/logrotate.d/ebpf-container-security
	@echo "✅ Log rotation configured"

uninstall-logrotate:
	@echo "🧹 Removing logrotate configuration..."
	@sudo rm -f /etc/logrotate.d/ebpf-container-security
	@echo "🗑️ Log rotation removed"
