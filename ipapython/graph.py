#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#


class Graph(object):
    """
    Simple oriented graph structure

    G = (V, E) where G is graph, V set of vertices and E list of edges.
    E = (tail, head) where tail and head are vertices
    """

    def __init__(self):
        self.vertices = set()
        self.edges = []
        self._adj = dict()

    def add_vertex(self, vertex):
        self.vertices.add(vertex)
        self._adj[vertex] = []

    def add_edge(self, tail, head):
        if tail not in self.vertices:
            raise ValueError("tail is not a vertex")
        if head not in self.vertices:
            raise ValueError("head is not a vertex")
        self.edges.append((tail, head))
        self._adj[tail].append(head)

    def remove_edge(self, tail, head):
        try:
            self.edges.remove((tail, head))
        except KeyError:
            raise ValueError(
                "graph does not contain edge: (%s, %s)" % (tail, head))
        self._adj[tail].remove(head)

    def remove_vertex(self, vertex):
        try:
            self.vertices.remove(vertex)
        except KeyError:
            raise ValueError("graph does not contain vertex: %s" % vertex)

        # delete _adjacencies
        del self._adj[vertex]
        for adj in self._adj.values():
            adj[:] = [v for v in adj if v != vertex]

        # delete edges
        edges = [e for e in self.edges if e[0] != vertex and e[1] != vertex]
        self.edges[:] = edges

    def get_tails(self, head):
        """
        Get list of vertices where a vertex is on the right side of an edge
        """
        return [e[0] for e in self.edges if e[1] == head]

    def get_heads(self, tail):
        """
        Get list of vertices where a vertex is on the left side of an edge
        """
        return [e[1] for e in self.edges if e[0] == tail]

    def bfs(self, start=None):
        """
        Breadth-first search traversal of the graph from `start` vertex.
        Return a set of all visited vertices
        """
        if not start:
            start = list(self.vertices)[0]
        visited = set()
        queue = [start]
        while queue:
            vertex = queue.pop(0)
            if vertex not in visited:
                visited.add(vertex)
                queue.extend(set(self._adj.get(vertex, [])) - visited)
        return visited
