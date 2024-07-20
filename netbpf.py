#!/usr/bin/env python3
import bcc
import socket

b = bcc.BPF(src_file=b"netbpf.c")

def decode_ip(ip: int) -> tuple[int]:
    return tuple((ip >> 8 * i) & 0xff for i in range(4))

def format_ip_port(ip: int, port: int) -> str:
    ip = ".".join(map(str, decode_ip(ip)))
    return f"{ip}:{port}"

def print_event(ctx, data, size, evtype):
    event = b[evtype].event(data)
    family = socket.AddressFamily(event.family)
    print(
        evtype,
        event.hash,
        format_ip_port(event.saddr, event.lport),
        format_ip_port(event.daddr, socket.ntohs(event.dport)),
        family.name,
        event.state,
        event.pid,
        event.task,
    )

b["ipv4_connect"].open_ring_buffer(lambda *args: print_event(*args, "ipv4_connect"))
b["ipv4_do_rcv"].open_ring_buffer(lambda *args: print_event(*args, "ipv4_do_rcv"))
b["ipv4_set_state"].open_ring_buffer(lambda *args: print_event(*args, "ipv4_set_state"))
while True:
    b.ring_buffer_poll()
