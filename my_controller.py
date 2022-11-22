# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 21:28
import sys
import time

from p4runtime_API.utils import UserError
from thrift_API.sswitch_thrift_API import SimpleSwitchThriftAPI

sys.path.append("/home/sinet41/yhx/new_devices/controller/simple_controller")

from p4runtime_API.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from utils.topo_util import load_topo


class MyController:
    def __init__(self, p4info_path, p4json_path):
        self.topo = load_topo("topo_all_server.json")
        self.controllers = {}
        self.thrift_controllers = {}
        self.connect_to_switches(p4info_path, p4json_path)

    def connect_to_switches(self, p4info_path, p4json_path):
        for p4Switch in self.topo.nodes:
            if p4Switch[0] == "s":
                device_id = self.topo.nodes[p4Switch]["device_id"]
                grpc_addr = self.topo.nodes[p4Switch]["grpc_addr"]
                thrift_addr = self.topo.nodes[p4Switch]["thrift_addr"]
                thrift_ip, thrift_port = thrift_addr.split(":")
                self.controllers[p4Switch] = SimpleSwitchP4RuntimeAPI(device_id=device_id,
                                                                      grpc_addr=grpc_addr,
                                                                      p4rt_path=p4info_path,
                                                                      json_path=p4json_path)
                self.thrift_controllers[p4Switch] = SimpleSwitchThriftAPI(thrift_ip=thrift_ip, thrift_port=thrift_port)

    def genSwitchIdTable(self):
        for p4Switch in self.thrift_controllers.keys():
            device_id = self.topo.nodes[p4Switch]["device_id"]
            device_id = str(device_id)
            thrift_controller = self.thrift_controllers[p4Switch]
            thrift_controller.table_add(table_name="MyEgress.swid", action_name="MyEgress.set_swid",
                                        match_keys=[], action_params=[device_id])

    def simple_ipv4_route(self):
        host_ip_dic = self.topo.getHost()
        host_list = list(host_ip_dic.keys())
        switch_controller = self.controllers.keys()
        for src in host_list:
            for dst in host_list:
                if src != dst:
                    path = self.topo.get_shortest_paths_between_nodes(src, dst)
                    for i in range(1, len(path) - 1):
                        sw_name = path[i]
                        dst_ip = host_ip_dic[dst]
                        next_hop_sw_name = path[i + 1]
                        next_hop_sw_mac = self.topo.node_to_node_mac(next_hop_sw_name, sw_name)[0]
                        next_hop_port = self.topo.node_to_node_port_num(sw_name, next_hop_sw_name)[0]
                        if sw_name in switch_controller:
                            self.controllers[sw_name].table_add("ipv4_lpm", "ipv4_forward", [dst_ip], [next_hop_sw_mac])
                            self.controllers[sw_name].table_add("l2_exact_table", "set_egress_port", [next_hop_sw_mac],
                                                                [next_hop_port])
                        else:
                            raise UserError("{} is not connected to the controller!".format(sw_name))

    def clear_ipv4route_table_entry(self):
        for sw, _controller in self.controllers.items():
            _controller.table_clear("ipv4_lpm")
            _controller.table_clear("l2_exact_table")

    def main(self):
        self.clear_ipv4route_table_entry()
        self.simple_ipv4_route()
        self.genSwitchIdTable()


if __name__ == "__main__":
    controller = MyController("my_link_monitor.p4info", "my_link_monitor.json")
    # controller = MyController("my_link_monitor_performance.p4info", "my_link_monitor_performance.json")
    controller.main()
