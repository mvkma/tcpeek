#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netbpf2.h"

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

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} events_ipv4 SEC(".maps");

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *skp, int state) {
  struct ipv4_event *event;
  struct sock_common sk_common;

  event = bpf_ringbuf_reserve(&events_ipv4, sizeof(*event), 0);
  if (!event)
    return 1;

  sk_common = BPF_CORE_READ(skp, __sk_common);

  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->uid = bpf_get_current_uid_gid();
  event->hash = sk_common.skc_hash;
  event->saddr = sk_common.skc_rcv_saddr;
  event->daddr = sk_common.skc_daddr;
  event->lport = sk_common.skc_num;
  event->dport = sk_common.skc_dport;
  event->family = sk_common.skc_family;
  event->state = sk_common.skc_state;

  bpf_get_current_comm(event->task, sizeof(event->task));

  bpf_ringbuf_submit(event, 0);

  return 0;
}

