#!/bin/bash

# Start detector in background
sudo ./bin/loader &
LOADER_PID=$!

# Trigger test
docker run --rm -it ubuntu sh -c \
"echo 'Normal container operation'; \
unshare --user && echo 'Potential escape attempt'"

# Check logs
echo -e "\nDetector Output:"
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "detect_container_escape"

# Cleanup
kill $LOADER_PID
