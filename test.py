# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 17:36
import socket
import struct
import networkx as nx
from utils.crc import Crc
from p4runtime_API.bytes_utils import parse_value

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
# a = Crc(16, 0x1021, True, 0x0000, True, 0x0000)
# a = crcmod.mkCrcFun(0x11021,0x0000,True,0x0000)
# b = parse_value("80",16)
# d = parse_value("80",16)
# e = socket.inet_aton("192.168.199.210")
# f = socket.inet_aton("192.168.199.102")
# g = e+f+b+d
# c = a.bit_by_bit_fast(g) % 8192
# c = a(g)% 8192
# print(type(c))
# end = time.time_ns()
# 8160
# print(end - start)
# int_ip = 123456789
# a = socket.inet_ntoa(struct.pack("I",socket.htonl(int_ip)))
# print(a)

# path = [1,2,3]
# total = 0
# boundary = []
# boundary.append(0)
# for i in path:
#     total+=i
#     boundary.append(total)
# print(boundary)
# a = str(1234)
# print(a)
# if not None:
#     print("aaaaa")
# a = None
# b = max(0.12,a)
# print(b)
# s1_bandwidth_result = (1,)
# s1_bandwidth = 0 if s1_bandwidth_result is None else s1_bandwidth_result[0]
# print(s1_bandwidth)
G = nx.Graph()
G.add_edge("x", "a", capacity=3.0)
G.add_edge("x", "b", capacity=1.0)
G.add_edge("a", "c", capacity=3.0)
G.add_edge("b", "c", capacity=5.0)
G.add_edge("b", "d", capacity=4.0)
G.add_edge("d", "e", capacity=2.0)
G.add_edge("c", "y", capacity=2.0)
G.add_edge("e", "y", capacity=3.0)
flow_value, flow_dict = nx.maximum_flow(G, "x", "y")
a = []



