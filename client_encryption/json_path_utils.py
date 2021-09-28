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
        if parent:
            current_node = __get_node(tree, parent, False)
        else:
            current_node = tree

        try:
            node_json = json.loads(node_str)
        except json.JSONDecodeError:
            node_json = node_str

        if to_set in current_node and type(current_node[to_set]) is dict and type(node_json) is dict:
            current_node[to_set].update(node_json)
        else:
            current_node[to_set] = node_json
    else:
        tree.clear()
        tree.update(json.loads(node_str))

    return tree


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

            if not node[to_delete]:
                del node[to_delete]

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


def __check_path_not_empty(path):
    if not path:
        raise ValueError("Cannot accept empty path")
