build:
    clang -O2 -target bpf -c src/detector.bpf.c -o src/detector.bpf.o
    clang -o bin/loader src/loader.c -lbpf
