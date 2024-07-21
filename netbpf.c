#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>

struct ipv4_data_t {
  u64 ts_us;
  u64 hash;
  u32 pid;
  u32 uid;
  u32 saddr;
  u32 daddr;
  u64 ip;
  u16 lport;
  u16 dport;
  unsigned short family;
  unsigned char state;
  unsigned char evtype;
  char task[TASK_COMM_LEN];
};

enum EVENTS {
  CONNECT = 1,
  SET_STATE = 2,
  DO_RCV_START = 3,
  DO_RCV_DONE = 4,
  DONE = 5
};

BPF_RINGBUF_OUTPUT(ipv4_events, 1 << 8);

static void set_ipv4_data(struct ipv4_data_t *data, struct sock *skp) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid;

  data->pid = pid;
  data->ip = 4;
  data->uid = bpf_get_current_uid_gid();
  data->ts_us = bpf_ktime_get_ns() / 1000;
  data->hash = skp->__sk_common.skc_hash;
  data->saddr = skp->__sk_common.skc_rcv_saddr;
  data->daddr = skp->__sk_common.skc_daddr;
  data->lport = skp->__sk_common.skc_num;
  data->dport = skp->__sk_common.skc_dport;
  data->family = skp->__sk_common.skc_family;
  data->state = skp->__sk_common.skc_state;
  bpf_get_current_comm(&data->task, sizeof(data->task));
}

KRETFUNC_PROBE(tcp_done, struct sock *skp, int ret) {
  // if (ret != 0) {
  //   return 0;
  // }

  if (skp->__sk_common.skc_family != AF_INET) {
    return 0;
  }

  struct ipv4_data_t data = {0};
  set_ipv4_data(&data, skp);
  data.evtype = DONE;
  ipv4_events.ringbuf_output(&data, sizeof(data), 0);

  return 0;
}

KRETFUNC_PROBE(tcp_set_state, struct sock *skp, int state, int ret) {
  // if (ret != 0) {
  //   return 0;
  // }

  if (skp->__sk_common.skc_family != AF_INET) {
    return 0;
  }

  struct ipv4_data_t data = {0};
  set_ipv4_data(&data, skp);
  data.evtype = SET_STATE;
  ipv4_events.ringbuf_output(&data, sizeof(data), 0);

  return 0;
}

KRETFUNC_PROBE(tcp_v4_connect, struct sock *skp, struct sockaddr *uaddr, int addr_len, int ret) {
  if (ret != 0) {
    return 0;
  }

  struct ipv4_data_t data = {0};
  set_ipv4_data(&data, skp);
  data.evtype = CONNECT;
  ipv4_events.ringbuf_output(&data, sizeof(data), 0);

  return 0;
}
