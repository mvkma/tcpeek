#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "netbpf2.skel.h"
#include "netbpf2.h"

static int event_handler(void *ctx, void *data, size_t size) {
  struct ipv4_event *event = data;

  printf("pid=%d, uid=%d, saddr=%d, daddr=%d, state=%d\n",
         event->pid,
         event->uid,
         event->saddr,
         event->daddr,
         event->state);

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

  while (ring_buffer__poll(ringbuffer, -1) >= 0) {
  }

  return 0;
}
