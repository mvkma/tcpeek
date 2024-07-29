#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "netbpf2.skel.h"
#include "netbpf2.h"

static int event_handler(void *ctx, void *data, size_t size) {
  struct ipv4_event *event = data;
  struct in_addr src;
  struct in_addr dst;
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];

  src.s_addr = event->saddr;
  dst.s_addr = event->daddr;

  if (event->family == AF_INET) {
    inet_ntop(AF_INET, &src, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &dst, daddr, sizeof(daddr));
  } else {
    inet_ntop(AF_INET6, &src, saddr, sizeof(saddr));
    inet_ntop(AF_INET6, &dst, daddr, sizeof(daddr));
  }

  printf("%-7d %-7d %-7d %-25s %-25s %-5d %-5d %llu\n",
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
  printf("%-7s %-7s %-7s %-25s %-25s %-5s %-5s %s\n",
         "PID", "TID", "UID", "SADDR", "DADDR", "STATE", "FAM", "HASH");

  while (ring_buffer__poll(ringbuffer, -1) >= 0) {
  }

  return 0;
}
