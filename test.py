# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 17:36
import json
import socket
import time

import crcmod
from scapy.layers.inet import IP

from crc import Crc
from p4runtime_API.bytes_utils import parse_value
from p4runtime_API.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from thrift_API.sswitch_thrift_API import SimpleSwitchThriftAPI

# a = SimpleSwitchP4RuntimeAPI(device_id=13, grpc_addr="192.168.199.182:50091",
#                              p4rt_path="my_link_monitor.p4info", json_path="my_link_monitor.json")
# a.table_clear("MyIngress.ipv4_lpm")
# a.table_add("MyIngress.ipv4_lpm", "ipv4_forward", ["10.0.3.2/24"], ["00:0a:f7:2a:a1:1a"])
# a.table_add("MyEgress.swid", "set_swid", [], ["13"])

# a = "192.168.199.182:9090"
# ip,port = a.split(":")
# print(ip)
# print(port)
# a = SimpleSwitchThriftAPI(thrift_port=9090,thrift_ip="192.168.199.182")
# b = a.get_custom_crc_calcs()
# print(type(b))
# print(b)

# a = "192.168.199.182"
# c="192.168.199.184"
# b = socket.inet_aton(a)
# d = socket.inet_aton(c)
# print(type(b))
# print(d)
# e = b + d
# print(type(e))
# print(e)


# start = time.time_ns()
a = Crc(16, 0x1021, True, 0x0000, True, 0x0000)
# a = crcmod.mkCrcFun(0x11021,0x0000,True,0x0000)
b = parse_value("80",16)
d = parse_value("80",16)
e = socket.inet_aton("192.168.199.210")
f = socket.inet_aton("192.168.199.102")
g = e+f+b+d
c = a.bit_by_bit_fast(g) % 8192
# c = a(g)% 8192
print(type(c))
# end = time.time_ns()
# 8160
# print(end - start)
