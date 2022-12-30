# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 21:28
import logging
import queue
import struct

import networkx

from utils.crc import Crc
from p4runtime_API.bytes_utils import parse_value
from p4runtime_API.utils import UserError
from thrift_API.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4runtime_API.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from utils.topo_util import load_topo
from utils.dbHelper import DbHelper
import socket

# crc16_ccitt
crc16_polinomial = 0x1021

# 最多处理的流数
FLOWLET_REGISTER_SIZE = 8192


class MyController:
    def __init__(self, p4info_path, p4json_path):
        self.topo = load_topo("topo_all_server.json")
        self.p4runtime_controllers = {}
        self.thrift_controllers = {}
        self.p4info_path = p4info_path
        self.p4json_path = p4json_path
        self.switchList = []
        self.hostList = []
        self.custom_calcs = {}
        self.hash = Crc(16, crc16_polinomial, True, 0x0000, True, 0x0000)
        # 要通过p4runtime下发的表
        self.switch_p4runtime_table = {}
        # 要通过thrift下发的表
        self.switch_thrift_table = {}
        self.logger = self.config_log()
        self.dbHelper = DbHelper(host="192.168.199.102", port=3306, user="root", password="mysql", database="cfint",
                                 charset='utf8')

    def config_log(self):
        logger = logging.getLogger("controller")
        logger.setLevel(logging.WARNING)
        handler = logging.FileHandler(filename="controller_log.txt", encoding="utf8")
        handler.setLevel(logging.WARNING)
        format_str = logging.Formatter("%(asctime)s- %(threadName)s - %(pathname)s[line:%(lineno)d] - %(message)s")
        handler.setFormatter(format_str)
        logger.addHandler(handler)
        return logger

    def getSwitchList(self):
        for node in self.topo.nodes:
            if node[0] == "s":
                self.switchList.append(node)

    def getHostList(self):
        for node in self.topo.nodes:
            if node[0] == "h":
                self.hostList.append(node)

    def connect_to_switches(self, p4info_path, p4json_path):
        for p4Switch in self.switchList:
            device_id = self.topo.nodes[p4Switch]["device_id"]
            grpc_addr = self.topo.nodes[p4Switch]["grpc_addr"]
            thrift_addr = self.topo.nodes[p4Switch]["thrift_addr"]
            thrift_ip, thrift_port = thrift_addr.split(":")
            thrift_port = int(thrift_port)
            self.p4runtime_controllers[p4Switch] = None
            while self.p4runtime_controllers[p4Switch] is None:
                self.p4runtime_controllers[p4Switch] = SimpleSwitchP4RuntimeAPI(device_id=device_id,
                                                                                grpc_addr=grpc_addr,
                                                                                p4rt_path=p4info_path,
                                                                                json_path=p4json_path)
            self.thrift_controllers[p4Switch] = None
            while self.thrift_controllers[p4Switch] is None:
                self.thrift_controllers[p4Switch] = SimpleSwitchThriftAPI(thrift_ip=thrift_ip, thrift_port=thrift_port)

    def get_custom_calcs(self):
        # 所有交换机的p4都相同，只获取一个即可
        swicth = self.switchList[0]
        thrift_controller = self.thrift_controllers[swicth]
        self.custom_calcs = thrift_controller.get_custom_crc_calcs()

    def genSwitchIdTable(self):
        """
        利用 thrift 下发交换机 ID
        :return:
        """
        for p4Switch in self.switchList:
            device_id = self.topo.nodes[p4Switch]["device_id"]
            device_id = str(device_id)
            thrift_controller = self.thrift_controllers[p4Switch]
            result = thrift_controller.table_add(table_name="MyEgress.swid", action_name="MyEgress.set_swid",
                                                 match_keys=[], action_params=[device_id])
            if not result:
                self.logger.error("Manually check: MyEgress.swid MyEgress.set_swid => %s", device_id)

    def simple_ipv4_route(self):
        host_ip_dic = self.topo.getHost()
        host_list = list(host_ip_dic.keys())
        switch_controller = self.p4runtime_controllers.keys()
        for src in host_list:
            for dst in host_list:
                if src != dst:
                    path = self.topo.get_shortest_paths_between_nodes(src, dst)
                    for i in range(1, len(path) - 1):
                        sw_name = path[i]
                        dst_ip = host_ip_dic[dst]
                        next_hop_sw_name = path[i + 1]
                        next_hop_sw_mac = self.topo.node_to_node_mac(next_hop_sw_name, sw_name)[0]
                        # next_hop_port = self.topo.node_to_node_port_num(sw_name, next_hop_sw_name)[0]
                        if sw_name in switch_controller:
                            result1 = self.p4runtime_controllers[sw_name].table_add("ipv4_lpm", "ipv4_forward",
                                                                                    [dst_ip],
                                                                                    [next_hop_sw_mac])
                            # result2 = self.p4runtime_controllers[sw_name].table_add("l2_exact_table", "set_egress_port",
                            #                                                         [next_hop_sw_mac],
                            #                                                         [next_hop_port])
                            if not result1:
                                self.logger.error("Manually check: table_add ipv4_lpm ipv4_forward %s => %s", dst_ip,
                                                  next_hop_sw_mac)
                            # if not result2:
                            #     self.logger.error("Manually check: table_add l2_exact_table set_egress_port %s => %s",
                            #                       next_hop_sw_mac, next_hop_port)
                        else:
                            raise UserError("{} is not connected to the controller!".format(sw_name))

    def clear_ipv4route_table_entry(self):
        for sw, _controller in self.p4runtime_controllers.items():
            _controller.table_clear("ipv4_lpm")
            _controller.table_clear("l2_exact_table")

    def init(self):
        self.getSwitchList()
        self.getHostList()
        # 连接控制器
        self.connect_to_switches(self.p4info_path, self.p4json_path)
        # 交换机状态初始化
        self.reset()
        # 配置控制面和数据面的hash函数
        self.hash_config()
        # 设置交换机ID
        self.tele_config()
        # 设置二层转发表
        self.gen_l2_exact_table()
        # 配置背景流量的路由表
        self.background_flow_config()

    def reset(self):
        for sw in self.switchList:
            thrift_controller: SimpleSwitchThriftAPI = self.thrift_controllers[sw]
            thrift_controller.reset_state()
            p4runtime_controller: SimpleSwitchP4RuntimeAPI = self.p4runtime_controllers[sw]
            p4runtime_controller.reset_state()

    def hash_config(self):
        self.get_custom_calcs()
        self.config_hash_function()

    def tele_config(self):
        self.genSwitchIdTable()

    def background_flow_config(self):
        self.simple_ipv4_route()

    def tunnel_dst_table(self):
        """
        利用 p4runtime 下发隧道终点的表项
        :return:
        """
        host_mac_dic = self.topo.getHostsMac()
        host_mac_list = list(host_mac_dic.values())
        for p4Switch in self.switchList:
            _controller: SimpleSwitchP4RuntimeAPI = self.p4runtime_controllers[p4Switch]
            result = _controller.table_add("tunnel_dst", "remove_tunnel_header", host_mac_list, [])
            if not result:
                self.logger.error("Manually check: table_add tunnel_dst remove_tunnel_header %s", host_mac_list)

    def check_compute_task_table(self):
        """
        假设 tcp 的目的端口为 6999 的流是需要优化的算力任务流量
        :return:
        """
        for p4Switch in self.switchList:
            _controller: SimpleSwitchP4RuntimeAPI = self.p4runtime_controllers[p4Switch]
            result = _controller.table_add("check_compute_task", "send_digest", ["6999"], [])
            if not result:
                self.logger.error("Manually check: table_add check_compute_task send_digest 6999")

    def config_hash_function(self):
        for p4Switch in self.thrift_controllers.keys():
            for custom_crc16_name, _width in self.custom_calcs:
                thrift_controller: SimpleSwitchThriftAPI = self.thrift_controllers[p4Switch]
                thrift_controller.set_crc16_parameters(name=custom_crc16_name, polynomial=crc16_polinomial,
                                                       initial_remainder=0x0000,
                                                       final_xor_value=0x0000, reflect_data=True,
                                                       reflect_remainder=True)

    def cal_tunnel_group(self, hdr_ipv4_srcAddr, hdr_ipv4_dstAddr, hdr_tcp_srcPort, hdr_tcp_dstPort) -> int:
        srcAddr = socket.inet_aton(hdr_ipv4_srcAddr)
        dstAddr = socket.inet_aton(hdr_ipv4_dstAddr)
        sPort = parse_value(hdr_tcp_srcPort, 16)
        dPort = parse_value(hdr_tcp_dstPort, 16)
        data = srcAddr + dstAddr + sPort + dPort
        return self.hash.bit_by_bit_fast(data) % FLOWLET_REGISTER_SIZE

    def gen_l2_exact_table(self):
        for sw in self.switchList:
            sw_neighbor_list = list(self.topo.adj[sw])
            for neighbor in sw_neighbor_list:
                neighbor_mac = self.topo.node_to_node_mac(neighbor, sw)[0]
                sw_port = self.topo.node_to_node_port_num(sw, neighbor)[0]
                result = self.p4runtime_controllers[sw].table_add("l2_exact_table", "set_egress_port",
                                                                  [neighbor_mac],
                                                                  [sw_port])
                if not result:
                    self.logger.error("Manually check: table_add l2_exact_table set_egress_port %s => %s", neighbor_mac,
                                      sw_port)

    def path_to_dstMAC(self, path):
        # path1 :: h1 s1 s6 s9 h3
        # s1 出 mac,s6 出 mac,s9 出 mac
        mac_dic = {}
        for i in range(1, len(path) - 1):
            next_hop_sw_mac = self.topo.node_to_node_mac(path[i + 1], path[i])[0]
            mac_dic[path[i]] = next_hop_sw_mac
        return mac_dic

    def update_topo_state(self, max_capacity):
        tele_round = self.get_newest_tele_round()
        switch_topo = self.topo.subgraph(self.switchList)
        for edge in switch_topo.edges:
            capacity = max_capacity - self.dbHelper.get_link_bandwidth(edge[0], edge[1], tele_round)
            self.topo.add_edge(edge[0], edge[1], capacity=capacity)
        return switch_topo, tele_round

    def gen_residual_graph(self, topo, path, bandwidth):
        for i in range(1, len(path) - 2):
            topo[path[i]][path[i + 1]]["capacity"] = topo[path[i]][path[i + 1]]["capacity"] - bandwidth
            if topo[path[i]][path[i + 1]]["capacity"] <= 0:
                topo.remove_edge(path[i], path[i + 1])

    def multipath_route(self, srcIP_str, dstIP_str, expect_bandwidth):
        # return [(path1,weight),(path2,weight),...]
        # path1 :: h1 s1 s6 s9 h3
        res = []
        max_bandwidth = 1000
        src = self.topo.getHostByIP(srcIP_str)
        dst = self.topo.getHostByIP(dstIP_str)
        src_gateway = list(self.topo[src].keys())[0]
        dst_gateway = list(self.topo[dst].keys())[0]
        switch_topo, tele_round = self.update_topo_state(max_bandwidth)
        switch_topo_deep = switch_topo.copy()
        while expect_bandwidth > 0:
            try:
                path_itr = networkx.shortest_simple_paths(switch_topo_deep, src_gateway, dst_gateway)
                path = next(path_itr)
                path.insert(0, src)
                path.append(dst)
                available_bandwidth = max_bandwidth - self.get_path_bandwidth(path, tele_round)
                res.append((path, available_bandwidth))
                expect_bandwidth -= available_bandwidth
                self.gen_residual_graph(switch_topo_deep, path, available_bandwidth)
            except networkx.NetworkXNoPath as e:
                print(str(e))
                break
        return res

    def gen_tunnel_table(self, flow_args):
        for flow_arg in flow_args:
            srcIP_str = flow_arg[0]
            dstIP_str = flow_arg[1]
            srcPort = flow_arg[2]
            dstPort = flow_arg[3]
            expect_bandwidth = flow_arg[4]
            tunnel_group = self.cal_tunnel_group(srcIP_str, dstIP_str, srcPort, dstPort)
            path_list = self.multipath_route(srcIP_str, dstIP_str, expect_bandwidth)
            path_boundary = [0]
            total_weight = 0
            for path in path_list:
                total_weight += path[1]
                path_boundary.append(total_weight)

            for sw in self.switchList:
                result1 = self.p4runtime_controllers[sw].table_add("tunnel_src", "add_tunnel_header",
                                                                   [str(tunnel_group)],
                                                                   [str(total_weight)])
                if not result1:
                    self.logger.error("Manually check: table_add tunnel_src add_tunnel_header %s => %s",
                                      str(tunnel_group), str(total_weight))

            for i in range(len(path_boundary) - 1):
                cur_path = path_list[i]
                tunnelId_range = str(path_boundary[i]) + ".." + str(path_boundary[i + 1] - 1)

                mac_dic = self.path_to_dstMAC(cur_path)
                for sw in mac_dic.keys():
                    result2 = self.p4runtime_controllers[sw].table_add("myTunnel_group_to_nhop", "tunnel_forward",
                                                                       [str(tunnel_group), tunnelId_range],
                                                                       [mac_dic[sw]])
                    if not result2:
                        self.logger.error("Manually check: table_add myTunnel_group_to_nhop tunnel_forward %s %s => %s",
                                          str(tunnel_group), tunnelId_range, mac_dic[sw])

    def config_digest(self):
        for sw in self.switchList:
            p4runtime_controller: SimpleSwitchP4RuntimeAPI = self.p4runtime_controllers[sw]
            p4runtime_controller.digest_enable(digest_name="flow_arg_t", max_timeout_ns=0, max_list_size=1,
                                               ack_timeout_ns=0)

    def unpack_digest(self, dig_list):
        flow_args = []
        for dig in dig_list.data:
            srcIP = int.from_bytes(dig.struct.members[0].bitstring, byteorder='big')
            dstIP = int.from_bytes(dig.struct.members[1].bitstring, byteorder='big')
            srcPort = int.from_bytes(dig.struct.members[2].bitstring, byteorder='big')
            dstPort = int.from_bytes(dig.struct.members[3].bitstring, byteorder='big')
            expect_bandwidth = int.from_bytes(dig.struct.members[4].bitstring, byteorder='big')
            srcIP_str = socket.inet_ntoa(struct.pack("I", socket.htonl(srcIP)))
            dstIP_str = socket.inet_ntoa(struct.pack("I", socket.htonl(dstIP)))
            flow_args.append((srcIP_str, dstIP_str, srcPort, dstPort, expect_bandwidth))
        return flow_args

    def recv_msg_digest(self, dig_list):
        flow_args = self.unpack_digest(dig_list)
        self.gen_tunnel_table(flow_args)

    def run_digest_loop(self):
        self.config_digest()
        while True:
            "TODO: 选定网关后就不要遍历所有交换机，改成只监听网关消息。"
            for sw in self.switchList:
                p4runtime_controller: SimpleSwitchP4RuntimeAPI = self.p4runtime_controllers[sw]
                dig_list = p4runtime_controller.get_digest_list()
                self.recv_msg_digest(dig_list)

    def get_path_bandwidth(self, path, tele_round):
        """
        返回对应遥测轮次的链路已用带宽
        :param path: 例如 [h1 s1 s3 s4 h3]
        :param tele_round: 遥测轮次，字符串类型
        :return:
        """
        path_bandwidth = 0
        for i in range(1, len(path) - 2):
            link_bandwidth = self.dbHelper.get_link_bandwidth(path[i], path[i + 1], tele_round)
            path_bandwidth = max(link_bandwidth, path_bandwidth)
        return path_bandwidth

    def get_path_latency(self, path, tele_round):
        """
        获取链路时延
        :param path: 例如 [h1 s1 s3 s4 h3]
        :param tele_round: 遥测轮次，字符串类型
        :return:
        """
        path_lantency = 0
        for i in range(1, len(path) - 2):
            link_latency = self.dbHelper.get_link_latency(path[i], path[i + 1], tele_round)
            path_lantency += link_latency
        return path_lantency

    def get_newest_tele_round(self):
        tele_round = self.dbHelper.get_valid_max_tele_round()
        if tele_round == -1:
            print("遥测还未完成，请等待后重试")
            return -1
        else:
            return tele_round

    def main(self):
        self.init()


if __name__ == "__main__":
    message_queue = queue.Queue(100)

    controller = MyController("my_link_monitor.p4info", "my_link_monitor.json")
    # controller = MyController("my_link_monitor_performance.p4info", "my_link_monitor_performance.json")
    controller.main()
