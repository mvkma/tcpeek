#ifndef __NETBPF2_H_
#define __NETBPF2_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct tcp_event {
  __u64 hash;
  __u32 pid;
  __u32 tid;
  __u32 uid;
  __u32 saddr4;
  __u32 daddr4;
  __u8 saddr6[16];
  __u8 daddr6[16];
  __u16 lport;
  __u16 dport;
  unsigned short family;
  unsigned char state;
  unsigned char evtype;
  char task[TASK_COMM_LEN];
};

#endif
