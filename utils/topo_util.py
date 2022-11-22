# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/10/10 21:30
import json

from networkx import node_link_graph

from utils.p4_network import P4Network


def load_topo(json_path):
    """Load the topology from the path provided.

    Args:
        json_path (string): path of the JSON file to load

    Returns:
        p4utils.utils.topology.NetworkGraph: the topology graph.
    """
    with open(json_path, 'r') as f:
        graph_dict = json.load(f)
        graph = node_link_graph(graph_dict)
    return P4Network(graph)