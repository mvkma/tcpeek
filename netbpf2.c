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

char HEADER_FORMAT[] = "%-7s %-7s %-7s %-25s %-25s %-20s %-8s %-8s %-8s %s\n";
char EVENTS_FORMAT[] = "%-7d %-7d %-7d %-25s %-25s %-20s %-8s %-8f %-8f %p\n";

static char* get_family_name(unsigned short family) {
  switch (family) {
  case AF_INET:
    return "AF_INET";
    break;
  case AF_INET6:
    return "AF_INET6";
    break;
  default:
    return "UNKNOWN";
    break;
  }
}

static char* get_tcp_state(unsigned char state) {
  switch (state) {
  case BPF_TCP_ESTABLISHED:
    return "TCP_ESTABLISHED";
    break;
  case BPF_TCP_SYN_SENT:
    return "TCP_SYN_SENT";
    break;
  case BPF_TCP_SYN_RECV:
    return "TCP_SYN_RECV";
    break;
  case BPF_TCP_FIN_WAIT1:
    return "TCP_FIN_WAIT1";
    break;
  case BPF_TCP_FIN_WAIT2:
    return "TCP_FIN_WAIT2";
    break;
  case BPF_TCP_TIME_WAIT:
    return "TCP_TIME_WAIT";
    break;
  case BPF_TCP_CLOSE:
    return "TCP_CLOSE";
    break;
  case BPF_TCP_CLOSE_WAIT:
    return "TCP_CLOSE_WAIT";
    break;
  case BPF_TCP_LAST_ACK:
    return "TCP_LAST_ACK";
    break;
  case BPF_TCP_LISTEN:
    return "TCP_LISTEN";
    break;
  case BPF_TCP_CLOSING:
    return "TCP_CLOSING";
    break;
  case BPF_TCP_NEW_SYN_RECV:
    return "TCP_NEW_SYN_RECV";
    break;
  case BPF_TCP_BOUND_INACTIVE:
    return "TCP_BOUND_INACTIVE";
    break;
  case BPF_TCP_MAX_STATES:
    return "TCP_MAX_STATES";
    break;
  default:
    return "UNKNOWN";
  }
}

static int print_event(struct tcp_event *event, char *saddr, char *daddr) {
  printf(EVENTS_FORMAT,
         event->pid,
         event->tid,
         event->uid,
         saddr,
         daddr,
         get_tcp_state(event->state),
         get_family_name(event->family),
         (double)event->bytes_received / 1024,
         (double)event->bytes_acked / 1024,
         event->skp);

  return 0;
}

static int handle_ipv4(struct tcp_event *event) {
  struct in_addr src;
  struct in_addr dst;
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];

  src.s_addr = event->saddr4;
  dst.s_addr = event->daddr4;

  inet_ntop(AF_INET, &src, saddr, sizeof(saddr));
  inet_ntop(AF_INET, &dst, daddr, sizeof(daddr));

  print_event(event, saddr, daddr);

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

  print_event(event, saddr, daddr);

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

  ringbuffer = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
  if (!ringbuffer) {
    fprintf(stderr, "Failed to create ringbuffer.\n");
    ring_buffer__free(ringbuffer);
    netbpf2_bpf__destroy(skel);
    return 1;
  }

  printf("Running...\n");
  printf(HEADER_FORMAT,
         "PID", "TID", "UID", "SADDR", "DADDR", "STATE", "FAMILY", "RX [KiB]", "TX [KiB]", "HASH");

  while (ring_buffer__poll(ringbuffer, -1) >= 0) {
  }

  return 0;
}
