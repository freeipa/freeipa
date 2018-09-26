#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

"""
set of functions and classes useful for management of domain level 1 topology
"""

from copy import deepcopy

from ipalib import _
from ipapython.graph import Graph

CURR_TOPOLOGY_DISCONNECTED = _("""
Replication topology in suffix '%(suffix)s' is disconnected:
%(errors)s""")

REMOVAL_DISCONNECTS_TOPOLOGY = _("""
Removal of '%(hostname)s' leads to disconnected topology in suffix '%(suffix)s':
%(errors)s""")


def create_topology_graph(masters, segments):
    """
    Create an oriented graph from topology defined by masters and segments.

    :param masters
    :param segments
    :returns: Graph
    """
    graph = Graph()

    for m in masters:
        graph.add_vertex(m['cn'][0])

    for s in segments:
        direction = s['iparepltoposegmentdirection'][0]
        left = s['iparepltoposegmentleftnode'][0]
        right = s['iparepltoposegmentrightnode'][0]
        try:
            if direction == u'both':
                graph.add_edge(left, right)
                graph.add_edge(right, left)
            elif direction == u'left-right':
                graph.add_edge(left, right)
            elif direction == u'right-left':
                graph.add_edge(right, left)
        except ValueError:  # ignore segments with deleted master
            pass

    return graph


def get_topology_connection_errors(graph):
    """
    Traverse graph from each master and find out which masters are not
    reachable.

    :param graph: topology graph where vertices are masters
    :returns: list of errors, error is: (master, visited, not_visited)
    """
    connect_errors = []
    master_cns = list(graph.vertices)
    master_cns.sort()
    for m in master_cns:
        visited = graph.bfs(m)
        not_visited = graph.vertices - visited
        if not_visited:
            connect_errors.append((m, list(visited), list(not_visited)))
    return connect_errors


def map_masters_to_suffixes(masters):
    masters_to_suffix = {}
    managed_suffix_attr = 'iparepltopomanagedsuffix_topologysuffix'

    for master in masters:
        if managed_suffix_attr not in master:
            continue

        managed_suffixes = master[managed_suffix_attr]

        if managed_suffixes is None:
            continue

        for suffix_name in managed_suffixes:
            try:
                masters_to_suffix[suffix_name].append(master)
            except KeyError:
                masters_to_suffix[suffix_name] = [master]

    return masters_to_suffix


def _create_topology_graphs(api_instance):
    """
    Construct a topology graph for each topology suffix
    :param api_instance: instance of IPA API
    """
    masters = api_instance.Command.server_find(
        u'', sizelimit=0, no_members=False)['result']

    suffix_to_masters = map_masters_to_suffixes(masters)

    topology_graphs = {}

    for suffix_name in suffix_to_masters:
        segments = api_instance.Command.topologysegment_find(
            suffix_name, sizelimit=0).get('result')

        topology_graphs[suffix_name] = create_topology_graph(
            suffix_to_masters[suffix_name], segments)

    return topology_graphs


def _format_topology_errors(topo_errors):
    msg_lines = []
    for error in topo_errors:
        msg_lines.append(
            _("Topology does not allow server %(server)s to replicate with "
              "servers:")
            % {'server': error[0]}
        )
        for srv in error[2]:
            msg_lines.append("    %s" % srv)

    return "\n".join(msg_lines)


class TopologyConnectivity:
    """
    a simple class abstracting the replication connectivity in managed topology
    """

    def __init__(self, api_instance):
        self.api = api_instance

        self.graphs = _create_topology_graphs(self.api)

    @property
    def errors(self):
        errors_by_suffix = {}
        for suffix in self.graphs:
            errors_by_suffix[suffix] = get_topology_connection_errors(
                self.graphs[suffix]
            )

        return errors_by_suffix

    def errors_after_master_removal(self, master_cn):
        graphs_before = deepcopy(self.graphs)

        for s in self.graphs:
            try:
                self.graphs[s].remove_vertex(master_cn)
            except ValueError:
                pass

        errors_after_removal = self.errors

        self.graphs = graphs_before

        return errors_after_removal

    def check_current_state(self):
        err_msg = ""
        for suffix in self.errors:
            errors = self.errors[suffix]
            if errors:
                err_msg = "\n".join([
                    err_msg,
                    CURR_TOPOLOGY_DISCONNECTED % dict(
                        suffix=suffix,
                        errors=_format_topology_errors(errors)
                    )])

            if err_msg:
                raise ValueError(err_msg)

    def check_state_after_removal(self, master_cn):
        err_msg = ""
        errors_after_removal = self.errors_after_master_removal(master_cn)

        for suffix in errors_after_removal:
            errors = errors_after_removal[suffix]
            if errors:
                err_msg = "\n".join([
                    err_msg,
                    REMOVAL_DISCONNECTS_TOPOLOGY % dict(
                        hostname=master_cn,
                        suffix=suffix,
                        errors=_format_topology_errors(errors)
                    )
                ])

        if err_msg:
            raise ValueError(err_msg)
