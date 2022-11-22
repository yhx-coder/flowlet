# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 17:36
import json

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
a = SimpleSwitchThriftAPI(thrift_port=9090,thrift_ip="192.168.199.182")
a.table_add(table_name="MyEgress.swid", action_name="MyEgress.set_swid",
                                         match_keys=[], action_params=["13"])