#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "netbpf2.skel.h"

int main(int argc, char **argv)
{
  struct netbpf2_bpf *skel;
  int err;

  skel = netbpf2_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton.\n");
    return 1;
  }

  skel->bss->my_pid = getpid();

  err = netbpf2_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton.\n");
    netbpf2_bpf__destroy(skel);
    return 1;
  }

  err = netbpf2_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton.\n");
    netbpf2_bpf__attach(skel);
    return 1;
  }

  printf("Started. Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe'\n");
  sleep(1);

  while (true) {
    fprintf(stderr, ".");
    sleep(1);
  }

  return 0;
}
