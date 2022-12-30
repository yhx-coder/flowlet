# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 20:36
import json
from itertools import islice

import networkx as nx
from networkx import node_link_graph

from my_controller import MyController
from utils.p4_network import P4Network


def k_shortest_paths(G, source, target, k, weight=None):
    return list(
        islice(nx.shortest_simple_paths(G, source, target, weight=weight), k)
    )


with open("topo_all_server.json", 'r') as f:
    graph_dict = json.load(f)
    graph = node_link_graph(graph_dict)
# a = k_shortest_paths(graph, "s10", "s15",18)
# i = 0
# for path in a:
#     print(path)
#     i += 1
# print(i)
switchList = []
for node in graph.nodes:
    if node[0] == 's':
        switchList.append(node)
sub = graph.subgraph(switchList)
sub_copy = sub.copy()
sub_copy.remove_edge("s10","s7")
sub_copy.remove_edge("s10","s8")
a = k_shortest_paths(sub_copy, "s10", "s15",18)
i = 0
for path in a:
    print(path)
    i += 1
print(i)
# path_itr = nx.shortest_simple_paths(sub_copy,"s10", "s15")
# path = next(path_itr)
# print(type(path))
# print(path)
#     for edge in graph.edges:
#         graph.add_edge(edge[0],edge[1], capacity=1000)
#     print(graph.edges(data="capacity"))
# M = graph["s1"]["s2"]
# network = P4Network(graph)
# path = network.get_shortest_paths_between_nodes("h1","h3")
# print(path)

# a = network.node_to_neighbor_name_dict["s6"]
# print(a)

# network.get_shortest_paths_between_nodes()

# controller = MyController("my_link_monitor.p4info", "my_link_monitor.json")
# a = controller.simple_ipv4_route()
# a = {"a":None}
# while(a["a"] == None):
#     if(a["a"]):
#         print("hhhhhh")
#     else:
#         print("ooooooo")
#         a["a"] = "ssss"
# print(a["a"])
