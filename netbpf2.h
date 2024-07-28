#ifndef __NETBPF2_H_
#define __NETBPF2_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct ipv4_event {
  __u64 hash;
  __u32 pid;
  __u32 uid;
  __u32 saddr;
  __u32 daddr;
  __u16 lport;
  __u16 dport;
  unsigned short family;
  unsigned char state;
  unsigned char evtype;
  char task[TASK_COMM_LEN];
};

#endif
