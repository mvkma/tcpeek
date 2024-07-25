#!/usr/bin/env python3
import bcc
import os
import socket

from enum import Enum

from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

class Event(Enum):
    CONNECT = 1
    SET_STATE = 2
    DO_RCV_START = 3
    DO_RCV_DONE = 4
    DONE = 5

class TCPState(Enum):
    TCP_ESTABLISHED = 1
    TCP_SYN_SENT = 2
    TCP_SYN_RECV = 3
    TCP_FIN_WAIT1 = 4
    TCP_FIN_WAIT2 = 5
    TCP_TIME_WAIT = 6
    TCP_CLOSE = 7
    TCP_CLOSE_WAIT = 8
    TCP_LAST_ACK = 9
    TCP_LISTEN = 10
    TCP_CLOSING = 11
    TCP_NEW_SYN_RECV = 12
    TCP_BOUND_INACTIVE = 13
    TCP_MAX_STATES = 14

b = bcc.BPF(src_file=b"netbpf.c", debug=bcc.DEBUG_PREPROCESSOR)

sockets = dict()

def decode_ip(ip: int) -> tuple[int]:
    return tuple((ip >> 8 * i) & 0xff for i in range(4))

def format_ip_port(ip: int, port: int) -> str:
    ip = ".".join(map(str, decode_ip(ip)))
    return f"{ip}:{port}"

def print_sockets():
    line_format = "{0: <20} {1: >20} {2: >20} {3: <10} {4: >25} {5: >6} {6}"
    # os.system("clear")
    print(line_format.format("evtype", "local", "remote", "family", "state", "pid", "task"))
    for k in sorted(sockets.keys()):
        v = sockets[k]
        match v[4]:
            case TCPState.TCP_CLOSE:
                prefix = f"{Fore.LIGHTBLACK_EX}"
            case TCPState.TCP_SYN_SENT:
                prefix = f"{Fore.YELLOW}"
            case TCPState.TCP_ESTABLISHED:
                prefix = f"{Fore.GREEN}"
            case _:
                prefix = ""
        print((prefix + line_format + f"{Style.RESET_ALL}").format(*v))

def update_event(ctx, data, size):
    event = b["ipv4_events"].event(data)
    sockets[event.hash] = (
        Event(event.evtype),
        format_ip_port(event.saddr, event.lport),
        format_ip_port(event.daddr, socket.ntohs(event.dport)),
        socket.AddressFamily(event.family).name,
        TCPState(event.state),
        event.pid,
        event.hash,
        # event.task
    )
    os.system("clear")
    print_sockets()

b["ipv4_events"].open_ring_buffer(update_event)

colorama_init()
while True:
    b.ring_buffer_poll()
