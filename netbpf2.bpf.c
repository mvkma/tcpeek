#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -idirafter /usr/lib/clang/18/include -idirafter /usr/local/include -idirafter /usr/include -c netbpf2.bpf.c -o netbpf2.tmp.bpf.o
 * bpftool gen object netbpf2.bpf.o netbpf2.tmp.bpf.o
 * bpftool gen skeleton netbpf2.bpf.o > netbpf2.skel.h
 *
 * clang -g -Wall -I. -c netbpf2.c -o netbpf2.o
 * clang -g -Wall netbpf2.o /usr/lib/libbpf.so -lelf -lz -o netbpf2
 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;

  if (pid != my_pid)
    return 0;

  bpf_printk("BPF triggered from PID %d.\n", pid);

  return 0;
}
