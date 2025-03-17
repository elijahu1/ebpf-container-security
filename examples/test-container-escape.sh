# examples/test-container-escape.sh
#!/bin/bash

set -e

echo "Starting container escape tests..."

# Run the loader in the background
sudo ./bin/loader &
LOADER_PID=$!
sleep 2  # Give the loader time to start

# Test 1: Simulate a container escape using unshare
echo "Running unshare test..."
if sudo unshare -UrmC bash -c "echo 'Inside unshared namespace'"; then
    echo "unshare test succeeded"
else
    echo "unshare test failed (may require privileged permissions)"
fi

# Test 2: Simulate a container escape using nsenter
echo "Running nsenter test..."
if sudo nsenter --mount=/proc/1/ns/mnt bash -c "echo 'Inside nsenter namespace'"; then
    echo "nsenter test succeeded"
else
    echo "nsenter test failed (may require privileged permissions)"
fi

# Test 3: Simulate a shell escape
echo "Running shell escape test..."
if sudo docker run --rm -it alpine sh -c "echo 'Inside container shell'"; then
    echo "docker shell test succeeded"
else
    echo "docker shell test failed (is Docker installed and running?)"
fi

# Stop the loader
echo "Stopping loader..."
sudo kill $LOADER_PID

echo "Tests completed!"
