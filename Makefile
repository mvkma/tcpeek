SRCS      := tcpeek.c
BPF_SRCS  := $(patsubst %.c,%.bpf.c,$(SRCS))
BPF_SKELS := $(patsubst %.bpf.c,%.skel.h,$(BPF_SRCS))
PROGS     := $(patsubst %.c,%,$(SRCS))
ARCH      := x86
VMLINUX   := vmlinux.h

BPF_INCLUDE_FLAGS := -I.
BPF_FLAGS := -g -O2
CLANG_INCLUDE_FLAGS := -I.
CLANG_FLAGS := -g -Wall
LINKER_FLAGS :=

.PHONY: all
all: $(PROGS)

.PHONY: skels
skels: $(BPF_SKELS)

.PHONY: clean
clean:
	rm -f $(addsuffix .tmp.bpf.o,$(PROGS))
	rm -f $(addsuffix .bpf.o,$(PROGS))
	rm -f $(addsuffix .o,$(PROGS))
	rm -f $(BPF_SKELS)
	rm -f $(PROGS)
	rm -f $(VMLINUX)

vmlinux: $(VMLINUX)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_SKELS): $(BPF_SRCS) $(VMLINUX)
	clang $(BPF_FLAGS) -target bpf -D__TARGET_ARCH_x86 $(BPF_INCLUDE_FLAGS) -c $(patsubst %.skel.h,%.bpf.c,$@) -o $(patsubst %.skel.h,%.tmp.bpf.o,$@)
	bpftool gen object $(patsubst %.skel.h,%.bpf.o,$@) $(patsubst %.skel.h,%.tmp.bpf.o,$@)
	bpftool gen skeleton $(patsubst %.skel.h,%.bpf.o,$@) > $@

$(addsuffix .o,$(PROGS)): $(SRCS) $(BPF_SKELS)
	clang $(CLANG_FLAGS) $(CLANG_INCLUDE_FLAGS) -c $(patsubst %.o,%.c,$@) -o $@

$(PROGS): $(addsuffix .o,$(PROGS))
	clang $(CLANG_FLAGS) $< /usr/lib/libbpf.so $(LINKER_FLAGS) -o $@
