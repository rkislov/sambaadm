#!/usr/bin/env python3
"""Request IPv4 and IPv6 leases through the isolated Samba Admin lab veth."""
import ipaddress
import os
import socket
import struct
import sys


def option4(code, value):
    return bytes((code, len(value))) + value


def options4(raw):
    result = {}
    while raw and raw[0] != 255:
        if raw[0] == 0:
            raw = raw[1:]
            continue
        code, size = raw[:2]
        result[code], raw = raw[2:2 + size], raw[2 + size:]
    return result


def option6(code, value):
    return struct.pack('!HH', code, len(value)) + value


def options6(raw):
    result = {}
    while raw:
        code, size = struct.unpack('!HH', raw[:4])
        result[code], raw = raw[4:4 + size], raw[4 + size:]
    return result


def lease4(node, mac):
    local, server = '198.18.77.2', f'198.18.77.{node}'
    xid = int.from_bytes(os.urandom(4), 'big')
    zero = bytes(4)
    header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 1, xid, 0, 0, zero, zero, zero,
                         socket.inet_aton(local), mac + bytes(10), b'', b'')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind((local, 67))
        client.settimeout(4)

        def exchange(kind, other=b''):
            client.sendto(header + b'\x63\x82\x53\x63' + option4(53, bytes((kind,))) + other + b'\xff', (server, 67))
            reply, _ = client.recvfrom(65535)
            assert int.from_bytes(reply[4:8], 'big') == xid
            return reply[16:20], options4(reply[240:])

        address, offer = exchange(1)
        assert offer[53] == b'\x02'
        ack, options = exchange(3, option4(50, address) + option4(54, offer[54]))
        assert options[53] == b'\x05' and ack == address
        address = ipaddress.IPv4Address(address)
        assert address in ipaddress.ip_network('198.18.77.0/24')
        print(f'DHCPv4 ACK {address} from {server}')


def lease6(node, mac):
    local, server = 'fd77:77:77::2', f'fd77:77:77::{node}'
    xid = os.urandom(3)
    client_id = option6(1, b'\x00\x03\x00\x01' + mac)
    association = option6(3, struct.pack('!III', 1, 0, 0))
    relay = (b'\x0c\x00' + socket.inet_pton(socket.AF_INET6, local) * 2 + option6(18, b'sambaadm-lab'))
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
        client.bind((local, 547))
        client.settimeout(4)

        def exchange(kind, extra=b''):
            message = bytes((kind,)) + xid + client_id + association + extra
            client.sendto(relay + option6(9, message), (server, 547))
            reply, _ = client.recvfrom(65535)
            assert reply[0] == 13
            inner = options6(reply[34:])[9]
            assert inner[1:4] == xid
            return inner[0], options6(inner[4:])

        kind, offer = exchange(1)
        assert kind == 2
        kind, reply = exchange(3, option6(2, offer[2]))
        assert kind == 7
        address = ipaddress.IPv6Address(options6(reply[3][12:])[5][:16])
        assert address in ipaddress.ip_network('fd77:77:77::/64')
        print(f'DHCPv6 REPLY {address} from {server}')


if __name__ == '__main__':
    socket.if_nametoindex('sa-client0')
    node = int(sys.argv[1])
    assert node in (11, 12)
    mac = b'\x02' + os.urandom(5)
    lease4(node, mac)
    lease6(node, mac)
