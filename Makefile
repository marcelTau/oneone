
all:
	cargo run

build_test:
	gcc test.c -o test.bin \
		-fno-asynchronous-unwind-tables \
		-fno-unwind-tables \
		-Wl,--no-eh-frame-hdr \
		-Wl,-z,nostack-size \
		-Wa,-mx86-used-note=no

.PHONY: all build_test
