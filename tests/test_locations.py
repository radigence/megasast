from megasast.engine import _node_range


class _Node:
    start_point = (2, 0)
    end_point = (2, 4)


def test_tree_sitter_columns_are_converted_to_sarif_columns():
    assert _node_range(_Node()) == (3, 1, 3, 5)
