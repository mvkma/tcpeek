#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tcpeek.h"

#define AF_INET		2
#define AF_INET6	10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, struct sock *);
} sockets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} events SEC(".maps");

static int kprobe_enter(struct sock *skp) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = pid_tgid;

  bpf_map_update_elem(&sockets, &tid, &skp, 0);

  return 0;
}

static int kprobe_exit(int ret) {
  struct tcp_event *event;
  struct sock *skp;
  struct sock **skpp;
  struct tcp_sock *tp;
  struct sock_common sk_common;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = pid_tgid;

  skpp = bpf_map_lookup_elem(&sockets, &tid);
  if (!skpp)
    return 0;

  if (ret != 0) {
    bpf_map_delete_elem(&sockets, &tid);
    return 1;
  }

  skp = *skpp;
  // TODO: I don't know why this is supposed to work.
  tp = (struct tcp_sock *)skp;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 1;

  sk_common = BPF_CORE_READ(skp, __sk_common);

  event->pid = pid;
  event->tid = tid;
  event->uid = bpf_get_current_uid_gid();
  event->hash = sk_common.skc_hash;
  event->lport = sk_common.skc_num;
  event->dport = sk_common.skc_dport;
  event->bytes_received = BPF_CORE_READ(tp, bytes_received);
  event->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
  event->family = sk_common.skc_family;
  event->state = sk_common.skc_state;
  event->skp = (void *)skp;

  switch (event->family) {
  case AF_INET:
    event->saddr4 = sk_common.skc_rcv_saddr;
    event->daddr4 = sk_common.skc_daddr;
    break;
  case AF_INET6:
    BPF_CORE_READ_INTO(&event->saddr6, &sk_common.skc_v6_rcv_saddr.in6_u, u6_addr32);
    BPF_CORE_READ_INTO(&event->daddr6, &sk_common.skc_v6_daddr.in6_u, u6_addr32);
  default:
    break;
  }

  bpf_get_current_comm(event->task, sizeof(event->task));

  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *skp, int state) {
  return kprobe_enter(skp);
}

SEC("kretprobe/tcp_set_state")
int BPF_KRETPROBE(tcp_set_state_ret, int ret) {
  return kprobe_exit(ret);
}
