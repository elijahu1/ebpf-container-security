build:
	mkdir -p bin
	clang -O2 -target bpf -c src/detector.bpf.c -o src/detector.bpf.o
	clang -o bin/loader src/loader.c -lbpf

test:
	chmod +x examples/test-container-escape.sh
	./examples/test-container-escape.sh

clean:
	rm -f src/*.o bin/loader
	rm -rf src/*.o bin/
