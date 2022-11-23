# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 20:36
import json

import networkx
from networkx import node_link_graph

from my_controller import MyController
from utils.p4_network import P4Network

# with open("topo.json", 'r') as f:
#     graph_dict = json.load(f)
#     graph = node_link_graph(graph_dict)
# M = graph["s1"]["s2"]
# network = P4Network(graph)
# path = network.get_shortest_paths_between_nodes("h1","h3")
# print(path)

# a = network.node_to_neighbor_name_dict["s6"]
# print(a)

# network.get_shortest_paths_between_nodes()

# controller = MyController("my_link_monitor.p4info", "my_link_monitor.json")
# a = controller.simple_ipv4_route()
a = {"a":None}
while(a["a"] == None):
    if(a["a"]):
        print("hhhhhh")
    else:
        print("ooooooo")
        a["a"] = "ssss"
print(a["a"])