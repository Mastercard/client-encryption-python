import json

_SEPARATOR = "."
_ROOT_SYMBOL = "$"


def __not_root(path): return path != _ROOT_SYMBOL


def __target_in_path(path, target): return target and target.startswith(path)


def get_node(tree, path, create=False):
    """Retrieve json or value given a path"""

    if not path:
        raise ValueError("Cannot accept empty path")

    current = tree
    if __not_root(path):
        current = __get_node(tree, path.split(_SEPARATOR), create)

    return current  # is a dict


def update_node(tree, path, node_str):
    """Update node with json or value in string format given a path"""

    __check_path_not_empty(path)

    if __not_root(path):
        parent = path.split(_SEPARATOR)
        to_set = parent.pop()
        current_node = __get_node(tree, parent, False) if parent else tree

        try:
            node_json = json.loads(node_str)
        except json.JSONDecodeError:
            node_json = node_str

        if type(current_node) is list:
            update_node_list(to_set, current_node, node_json)
        elif to_set in current_node and type(current_node[to_set]) is dict and type(node_json) is dict:
            current_node[to_set].update(node_json)
        else:
            current_node[to_set] = node_json
    else:
        tree.clear()
        tree.update(json.loads(node_str))

    return tree


def update_node_list(to_set, current_node, node_json):
    if to_set in current_node[0] and type(current_node[0][to_set]) is dict and type(node_json) is dict:
        current_node[0][to_set].update(node_json)
    else:
        current_node[0][to_set] = node_json


def pop_node(tree, path):
    """Retrieve and delete json or value given a path"""

    __check_path_not_empty(path)

    if __not_root(path):
        parent = path.split(_SEPARATOR)
        to_delete = parent.pop()
        if parent:
            node = __get_node(tree, parent, False)
        else:
            node = tree

        if type(node) is list:
            deleted_elem = node[0].pop(to_delete)
        else:
            deleted_elem = node.pop(to_delete)
        if isinstance(deleted_elem, str):
            return deleted_elem
        else:
            return json.dumps(deleted_elem)

    else:
        node = json.dumps(tree)
        tree.clear()
        return node


def cleanup_node(tree, path, target):
    """Remove a node if not in target path and no child is found given a path"""

    __check_path_not_empty(path)

    if __not_root(path):
        if not __target_in_path(path, target):
            parent = path.split(_SEPARATOR)
            to_delete = parent.pop()
            if parent:
                node = __get_node(tree, parent, False)
            else:
                node = tree
            if type(node) is list and not node[0][to_delete]:
                del node[0][to_delete]
            elif not node[to_delete]:
                del node[to_delete]

    else:
        if not tree:
            tree.clear()

    return tree


def __get_node(tree, node_list, create):
    current = tree
    last_node = node_list.pop()

    for node in node_list:
        if type(current) is list:
            current = current[0][node]
        else:
            current = current[node]

    if type(current) is not dict and type(current) is not list:
        raise ValueError("'" + current + "' is not of dict type")

    if type(current) is list:
        if not current and create:
            d = dict()
            d[last_node] = {}
            current.append(d)
        elif last_node not in current[0] and create:
            current[0][last_node] = {}
        return current[0][last_node]
    elif last_node not in current and create:
        current[last_node] = {}

    return current[last_node]


def __check_path_not_empty(path):
    if not path:
        raise ValueError("Cannot accept empty path")
