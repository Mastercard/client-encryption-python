import unittest
import json

import client_encryption.json_path_utils as to_test


class JsonPathUtilsTest(unittest.TestCase):

    @staticmethod
    def __get_sample_json():
        return {
            "node1": {
                "node2": {
                    "colour": "red",
                    "shape": "circle",
                    "position": {
                        "lat": 1,
                        "long": 3
                    }
                }
            }
        }

    @staticmethod
    def __get_array_sample_json():
        return {
            "node1": [
                {
                    "node2": {
                    "colour": "red",
                    "shape": "circle",
                    "position": {
                        "lat": 1,
                        "long": 3
                        }
                    }
                }
            ]
        }

    def test_get_node(self):
        sample_json = self.__get_sample_json()

        node = to_test.get_node(sample_json, "$")
        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual(sample_json, node)

        node = to_test.get_node(sample_json, "node1")
        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual(sample_json["node1"], node)

        node = to_test.get_node(sample_json, "node1.node2")
        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual(sample_json["node1"]["node2"], node)

        node = to_test.get_node(sample_json, "node1.node2.shape")
        self.assertIsInstance(node, str, "Not a string")
        self.assertEqual("circle", node)

        node = to_test.get_node(sample_json, "node1.node2.position.lat")
        self.assertIsInstance(node, int, "Not an int")
        self.assertEqual(1, node)

        node = to_test.get_node(sample_json, "node1.node2.newnode", True)
        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual({}, node)

    def test_get_node_empty_path(self):
        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.get_node, sample_json, None)

        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.get_node, sample_json, "")

    def test_get_node_not_a_dict(self):
        sample_json = self.__get_sample_json()

        self.assertRaises(ValueError, to_test.get_node, sample_json, "node1.node2.shape.newnode")
        self.assertRaises(ValueError, to_test.get_node, sample_json, "node1.node2.shape.newnode", True)

    def test_get_node_not_existing(self):
        sample_json = self.__get_sample_json()

        # create=False
        self.assertRaises(KeyError, to_test.get_node, sample_json, "node1.node2.newnode")
        # too many new nodes
        self.assertRaises(KeyError, to_test.get_node, sample_json, "node1.node2.newnode.newnode2", True)

    def test_update_node(self):
        sample_json = self.__get_sample_json()
        node = to_test.update_node(sample_json, "$", '{"node3": {"brightness": 6}}')

        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual({"node3": {
                                "brightness": 6
                                }
                              }, node)

        sample_json = self.__get_sample_json()
        node = to_test.update_node(sample_json, "node1", '{"node3": {"brightness": 6}}')

        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual({"node1": {
                                "node2": {
                                    "colour": "red",
                                    "shape": "circle",
                                    "position": {
                                        "lat": 1,
                                        "long": 3
                                    }
                                },
                                "node3": {
                                    "brightness": 6
                                }
                               }
                              }, node)

        sample_json = self.__get_sample_json()
        node = to_test.update_node(sample_json, "node1.node2", '{"node3": {"brightness": 6}}')

        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual({"node1": {
                                "node2": {
                                    "colour": "red",
                                    "shape": "circle",
                                    "position": {
                                        "lat": 1,
                                        "long": 3
                                    },
                                    "node3": {
                                        "brightness": 6
                                    }
                                }
                               }
                              }, node)

        sample_json = self.__get_sample_json()
        node = to_test.update_node(sample_json, "node1.node2.new", '{"node3": {"brightness": 6}}')

        self.assertIsInstance(node, dict, "Not a dict")
        self.assertDictEqual({"node1": {
                                "node2": {
                                    "colour": "red",
                                    "shape": "circle",
                                    "position": {
                                        "lat": 1,
                                        "long": 3
                                    },
                                    "new": {
                                        "node3": {
                                            "brightness": 6
                                            }
                                        }
                                    }
                                }
                              }, node)

    def test_update_node_empty_path(self):
        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.update_node, sample_json, None, '{"node3": {"brightness": 6}}')

        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.update_node, sample_json, "", '{"node3": {"brightness": 6}}')

    def test_update_node_not_json(self):
        sample_json = self.__get_sample_json()
        node = to_test.update_node(sample_json, "node1.node2", "not a json string")

        self.assertIsInstance(node["node1"]["node2"], str, "not a json string")

    def test_update_node_array_with_str(self):
        sample_json = self.__get_array_sample_json()
        node = to_test.update_node(sample_json, "node1.node2", "not a json string")

        self.assertIsInstance(node["node1"][0]["node2"], str, "not a json string")

    def test_update_node_array_with_json_str(self):
        sample_json = self.__get_array_sample_json()
        node = to_test.update_node(sample_json, "node1.node2", '{"position": {"brightness": 6}}')

        self.assertIsInstance(node["node1"][0]["node2"]["position"], dict)
        self.assertDictEqual({'node1': [
                                {'node2': {
                                    'colour': 'red',
                                    'shape': 'circle',
                                    'position': {
                                        'brightness': 6
                                    }
                                }
                                }
                            ]}, node)


    def test_update_node_primitive_type(self):
        sample_json = self.__get_sample_json()

        node = to_test.update_node(sample_json, "node1.node2", '"I am a primitive data type"')

        self.assertIsInstance(node["node1"]["node2"], str, "Not a string")
        self.assertDictEqual({"node1": {
                                "node2": "I am a primitive data type"
                                }
                              }, node)

        node = to_test.update_node(sample_json, "node1.node2", '4378462')

        self.assertIsInstance(node["node1"]["node2"], int, "Not an int")
        self.assertDictEqual({"node1": {
                                "node2": 4378462
                                }
                              }, node)

        node = to_test.update_node(sample_json, "node1.node2", 'true')

        self.assertIsInstance(node["node1"]["node2"], bool, "Not a bool")
        self.assertDictEqual({"node1": {
                                "node2": True
                                }
                              }, node)

    def test_pop_node(self):
        original_json = self.__get_sample_json()

        sample_json = self.__get_sample_json()
        node = to_test.pop_node(sample_json, "$")
        self.assertIsInstance(node, str, "Not a string")
        self.assertDictEqual(original_json, json.loads(node))

        self.assertDictEqual({}, sample_json)

        sample_json = self.__get_sample_json()
        node = to_test.pop_node(sample_json, "node1")
        self.assertIsInstance(node, str, "Not a string")
        self.assertDictEqual(original_json["node1"], json.loads(node))

        self.assertDictEqual({}, sample_json)

        sample_json = self.__get_sample_json()
        node = to_test.pop_node(sample_json, "node1.node2")
        self.assertIsInstance(node, str, "Not a string")
        self.assertDictEqual(original_json["node1"]["node2"], json.loads(node))

        self.assertDictEqual({"node1": {}}, sample_json)

        sample_json = self.__get_sample_json()
        node = to_test.pop_node(sample_json, "node1.node2.colour")
        self.assertIsInstance(node, str, "Not a string")
        self.assertEqual("red", node)
        self.assertDictEqual({"node1": {
                                "node2": {
                                    "shape": "circle",
                                    "position": {
                                        "lat": 1,
                                        "long": 3
                                    }
                                }
                               }
                              }, sample_json)

    def test_pop_node_empty_path(self):
        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.pop_node, sample_json, None)

        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.pop_node, sample_json, "")

    def test_pop_node_not_existing(self):
        sample_json = self.__get_sample_json()

        self.assertRaises(KeyError, to_test.pop_node, sample_json, "node0")
        self.assertRaises(KeyError, to_test.pop_node, sample_json, "node1.node2.node3")

    def test_cleanup_node(self):
        original_json = self.__get_sample_json()

        sample_json = self.__get_sample_json()
        node = to_test.cleanup_node(sample_json, "node1.node2.colour", "target")
        self.assertIsInstance(node, dict, "Not a dictionary")
        self.assertDictEqual(original_json, node)
        self.assertDictEqual(original_json, sample_json)

        sample_json = self.__get_sample_json()
        del sample_json["node1"]["node2"]["colour"]
        del sample_json["node1"]["node2"]["shape"]
        del sample_json["node1"]["node2"]["position"]
        node = to_test.cleanup_node(sample_json, "node1.node2", "target")
        self.assertIsInstance(node, dict, "Not a dictionary")
        self.assertDictEqual({"node1": {}}, node)
        self.assertDictEqual({"node1": {}}, sample_json)

    def test_cleanup_node_in_target(self):
        sample_json = self.__get_sample_json()
        del sample_json["node1"]["node2"]["colour"]
        del sample_json["node1"]["node2"]["shape"]
        del sample_json["node1"]["node2"]["position"]
        node = to_test.cleanup_node(sample_json, "node1.node2", "node1.node2.target")
        self.assertIsInstance(node, dict, "Not a dictionary")
        self.assertDictEqual({"node1": {"node2": {}}}, node)
        self.assertDictEqual({"node1": {"node2": {}}}, sample_json)

    def test_cleanup_node_empty_path(self):
        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.cleanup_node, sample_json, None, "target")

        sample_json = self.__get_sample_json()
        self.assertRaises(ValueError, to_test.cleanup_node, sample_json, "", "target")

    def test_cleanup_node_empty_target(self):
        sample_json = self.__get_sample_json()
        del sample_json["node1"]["node2"]["colour"]
        del sample_json["node1"]["node2"]["shape"]
        del sample_json["node1"]["node2"]["position"]
        node = to_test.cleanup_node(sample_json, "node1.node2", None)
        self.assertIsInstance(node, dict, "Not a dictionary")
        self.assertDictEqual({"node1": {}}, node)
        self.assertDictEqual({"node1": {}}, sample_json)

        sample_json = self.__get_sample_json()
        del sample_json["node1"]["node2"]["colour"]
        del sample_json["node1"]["node2"]["shape"]
        del sample_json["node1"]["node2"]["position"]
        node = to_test.cleanup_node(sample_json, "node1.node2", "")
        self.assertIsInstance(node, dict, "Not a dictionary")
        self.assertDictEqual({"node1": {}}, node)
        self.assertDictEqual({"node1": {}}, sample_json)

    def test_cleanup_node_not_existing(self):
        sample_json = self.__get_sample_json()

        self.assertRaises(KeyError, to_test.cleanup_node, sample_json, "node0", "target")
        self.assertRaises(KeyError, to_test.cleanup_node, sample_json, "node1.node2.node3", "target")
