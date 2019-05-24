import json


_SEPARATOR = "."
_ROOT_SYMBOL = "$"


def __not_root(path): return path != _ROOT_SYMBOL


def get_node(tree, path, create=False):
    """Retrieve json or value given a path"""

    current = tree
    if path and __not_root(path):
        current = __get_node(tree, path.split(_SEPARATOR), create)

    elif not path:
        raise ValueError("Cannot accept empty path")

    return current


def update_node(tree, path, node_str):
    """Update node with json or value in string format given a path"""

    if path and __not_root(path):
        parent = path.split(_SEPARATOR)
        to_set = parent.pop()
        if parent:
            current_node = __get_node(tree, parent, False)
        else:
            current_node = tree

        if to_set in current_node and type(current_node[to_set]) is dict:
            current_node[to_set].update(json.loads(node_str))
        else:
            current_node[to_set] = json.loads(node_str)

    elif not path:
        raise ValueError("Cannot accept empty path")

    else:
        tree.clear()
        tree.update(json.loads(node_str))

    return tree


def pop_node(tree, path):
    """Retrieve and delete json or value given a path"""

    if path and __not_root(path):
        parent = path.split(_SEPARATOR)
        to_delete = parent.pop()
        if parent:
            node = __get_node(tree, parent, False)
        else:
            node = tree

        return json.dumps(node.pop(to_delete))

    elif not path:
        raise ValueError("Cannot accept empty path")

    else:
        node = json.dumps(tree)
        tree.clear()
        return node


def cleanup_node(tree, path):
    """Remove a node if no child is found give a path"""

    if path and __not_root(path):
        parent = path.split(_SEPARATOR)
        to_delete = parent.pop()
        if parent:
            node = __get_node(tree, parent, False)
        else:
            node = tree

        if not node[to_delete]:
            del node[to_delete]

    elif not path:
        raise ValueError("Cannot accept empty path")

    else:
        if not tree:
            tree.clear()

    return tree


def __get_node(tree, node_list, create):
    current = tree
    last_node = node_list.pop()

    for node in node_list:
        current = current[node]

    if type(current) is not dict:
        raise ValueError("'" + current + "' is not of dict type")

    if last_node not in current and create:
        current[last_node] = {}

    return current[last_node]
