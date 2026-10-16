import pytest

from webchallscan.planner import plan_inventory


def inventory():
    return {
        "schema": "webchallscan/network-inventory-v1",
        "origin": "https://ctf.example",
        "endpoints": [
            {"method": "POST", "path": "/api/graphql", "parameters": [], "type": "XHR"},
            {"method": "GET", "path": "/search", "parameters": ["q"], "type": "Fetch"},
        ],
    }


def test_offline_plan_records_no_active_tests():
    plan = plan_inventory(inventory(), "https://ctf.example")
    assert plan["active_tests_executed"] == 0
    assert plan["endpoint_count"] == 2
    assert "graphql-operation-discovery" in plan["checks"][0]["checks"]
    assert all(x["active_test_status"] == "not-executed" for x in plan["checks"])


def test_origin_mismatch_is_rejected():
    with pytest.raises(ValueError):
        plan_inventory(inventory(), "https://other.example")


def test_non_path_and_bad_schema_rejected():
    data = inventory()
    data["endpoints"][0]["path"] = "//external.test"
    with pytest.raises(ValueError):
        plan_inventory(data)
    data["schema"] = "unknown"
    with pytest.raises(ValueError):
        plan_inventory(data)
