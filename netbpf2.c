#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "netbpf2.skel.h"
#include "netbpf2.h"

static int handle_ipv4(struct tcp_event *event) {
  struct in_addr src;
  struct in_addr dst;
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];

  src.s_addr = event->saddr4;
  dst.s_addr = event->daddr4;

  inet_ntop(AF_INET, &src, saddr, sizeof(saddr));
  inet_ntop(AF_INET, &dst, daddr, sizeof(daddr));

  printf("%-3d %-7d %-7d %-7d %-25s %-25s %-5d %-5d %llu (ipv4)\n",
         event->evtype,
         event->pid,
         event->tid,
         event->uid,
         saddr,
         daddr,
         event->state,
         event->family,
         event->hash);

  return 0;
}

static int handle_ipv6(struct tcp_event *event) {
  struct in6_addr src;
  struct in6_addr dst;
  char saddr[INET6_ADDRSTRLEN];
  char daddr[INET6_ADDRSTRLEN];

  memcpy(src.s6_addr, event->saddr6, sizeof(src.s6_addr));
  memcpy(dst.s6_addr, event->daddr6, sizeof(dst.s6_addr));

  inet_ntop(AF_INET6, &src, saddr, sizeof(saddr));
  inet_ntop(AF_INET6, &dst, daddr, sizeof(daddr));

  printf("%-3d %-7d %-7d %-7d %-25s %-25s %-5d %-5d %llu (ipv6)\n",
         event->evtype,
         event->pid,
         event->tid,
         event->uid,
         saddr,
         daddr,
         event->state,
         event->family,
         event->hash);

  return 0;
}

static int event_handler(void *ctx, void *data, size_t size) {
  struct tcp_event *event = data;

  switch (event->family) {
  case AF_INET:
    return handle_ipv4(data);
    break;
  case AF_INET6:
    return handle_ipv6(data);
    break;
  default:
    break;
  }

  return 0;
}

int main(int argc, char **argv)
{
  struct netbpf2_bpf *skel;
  struct ring_buffer *ringbuffer;
  int err;

  skel = netbpf2_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton.\n");
    return 1;
  }

  err = netbpf2_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton.\n");
    netbpf2_bpf__destroy(skel);
    return 1;
  }

  err = netbpf2_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton.\n");
    netbpf2_bpf__destroy(skel);
    return 1;
  }

  ringbuffer = ring_buffer__new(bpf_map__fd(skel->maps.events_ipv4), event_handler, NULL, NULL);
  if (!ringbuffer) {
    fprintf(stderr, "Failed to create ringbuffer.\n");
    ring_buffer__free(ringbuffer);
    netbpf2_bpf__destroy(skel);
    return 1;
  }

  printf("Running...\n");
  printf("%-3s %-7s %-7s %-7s %-25s %-25s %-5s %-5s %s\n",
         "E", "PID", "TID", "UID", "SADDR", "DADDR", "STATE", "FAM", "HASH");

  while (ring_buffer__poll(ringbuffer, -1) >= 0) {
  }

  return 0;
}
