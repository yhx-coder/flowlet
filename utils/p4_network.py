# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 21:35
import networkx as nx


class P4Network(nx.Graph):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.node_name_to_portNum = self.__name_to_portNum()
        self.node_name_to_mac = self.__name_to_mac()
        self.node_to_neighbor_name_dict = self.__connected_name_dic()

    def getDestination(self):
        node_to_ip = {}
        ip_to_port = {}
        for node in self.nodes:
            for portId, portInfo in self.nodes[node]["ports"].items():
                if portInfo['ip']:
                    node_to_ip[node] = (portInfo["ip"], portInfo["mac"])
                    ip_to_port[portInfo["ip"]] = portId
        return node_to_ip, ip_to_port

    def getHost(self):
        host_ip_dic = {}
        for node in self.nodes:
            if node[0] == "h":
                host_ip_dic[node] = self.nodes[node]["ip"]
        return host_ip_dic

    def getHostsMac(self):
        host_mac_dic = {}
        for node in self.nodes:
            if node[0] == "h":
                host_mac_dic[node] = self.nodes[node]["mac"]
        return host_mac_dic

    def __name_to_portNum(self):
        node_name_to_portNum = {}
        for node in self.nodes:
            if node[0] == "s":
                node_name_to_portNum[node] = {}
                for portId, portInfo in self.nodes[node]["ports"].items():
                    name = portInfo["name"]
                    portNum = portInfo["number"]
                    node_name_to_portNum[node][name] = portNum
        return node_name_to_portNum

    def __name_to_mac(self):
        node_name_to_mac = {}
        for node in self.nodes:
            node_name_to_mac[node] = {}
            if node[0] == "s":
                for portId, portInfo in self.nodes[node]["ports"].items():
                    name = portInfo["name"]
                    mac = portInfo["mac"]
                    node_name_to_mac[node][name] = mac
            elif node[0] == "h":
                portName = self.nodes[node]["port"]
                host_mac = self.nodes[node]["mac"]
                node_name_to_mac[node][portName] = host_mac
        return node_name_to_mac

    def __connected_name_dic(self):
        node_to_neighbor_name_dict = {}
        for node in self.nodes:
            node_to_neighbor_name_dict[node] = {}
        settled_set = set()
        for node, neighbors in self.adj.items():
            for neighbor, edgeAttr in neighbors.items():
                if (neighbor, node) not in settled_set:
                    source_device = edgeAttr["source_device"]
                    target_device = edgeAttr["target_device"]

                    node_to_neighbor_name_dict[source_device][target_device] \
                        = (edgeAttr["source-inf"], edgeAttr["target-inf"])
                    node_to_neighbor_name_dict[target_device][source_device] \
                        = (edgeAttr["target-inf"], edgeAttr["source-inf"])
                    settled_set.add((neighbor, node))
                    settled_set.add((node, neighbor))
        return node_to_neighbor_name_dict

    def node_to_node_port_num(self, node1, node2):
        node1_name, node2_name = self.node_to_neighbor_name_dict[node1][node2]
        if node1[0] != "h" and node2[0] != "h":
            return self.node_name_to_portNum[node1][node1_name], self.node_name_to_portNum[node2][node2_name]
        elif node1[0] == "h" and node2[0] != "h":
            return self.node_name_to_portNum[node2][node2_name], self.node_name_to_portNum[node2][node2_name]
        elif node1[0] != "h" and node2[0] == "h":
            return self.node_name_to_portNum[node1][node1_name], self.node_name_to_portNum[node1][node1_name]

    def node_to_node_mac(self, node1, node2):
        node1_name, node2_name = self.node_to_neighbor_name_dict[node1][node2]
        return self.node_name_to_mac[node1][node1_name], self.node_name_to_mac[node2][node2_name]

    def get_shortest_paths_between_nodes(self, node1, node2):
        return nx.shortest_path(self, node1, node2)
