"""Regression coverage for literal API route hints in common JS config shapes."""
from webchallscan.scanner import Response, Scanner


def test_reordered_axios_jquery_and_fetch_method_configs_are_detected():
    source = """
    axios({url:'/api/create', method:'POST'});
    axios.request({method:'DELETE',url:'/api/delete'});
    $.ajax({type:'PATCH', url:'/v2/update'});
    fetch('/admin/change', {credentials:'include', method:'PUT'});
    fetch('/api/ignore', {headers: {'X-Test': 'value'}, method:dynamic});
    axios({url:'/api/dynamic', method: unknown});
    """
    result = Scanner._static_api_hints(source)
    assert ("POST", "/api/create") in result
    assert ("DELETE", "/api/delete") in result
    assert ("PATCH", "/v2/update") in result
    assert ("PUT", "/admin/change") in result
    assert ("POST", "/api/dynamic") not in result
    assert all(method in {"POST", "PUT", "PATCH", "DELETE", "UNKNOWN"}
               for method, _ in result)


def test_js_hints_remain_same_origin_and_zero_request():
    scanner = Scanner("https://lab.example/")
    js = Response("https://lab.example/static/app.js", 200, {},
                  """axios({url:'/api/private', method:'POST'});
                  axios.request({method:'DELETE',url:'https://outside.example/erase'});
                  $.ajax({type:'PATCH', url:'/api/edit'});
                  fetch('/api/change', {credentials:'include',method:'PUT'});""")
    findings = scanner._js_api_findings(js)
    paths = {f.url for f in findings}
    assert "https://lab.example/api/private" in paths
    assert "https://lab.example/api/edit" in paths
    assert "https://lab.example/api/change" in paths
    assert "https://outside.example/erase" not in paths
    assert all(f.rule == "WEB-JS-API-HINT-001" for f in findings)
    assert all(f.severity == "info" and f.confidence == "low" for f in findings)
    assert scanner.requests_sent == 0


def test_dynamic_url_concatenation_not_attributed_to_explicit_post():
    source = """axios({method:'POST', url:'/api/' + variable});
    axios({url:'/api/{id}',method:'POST'});"""
    result = Scanner._static_api_hints(source)
    assert ("POST", "/api/{id}") not in result
    assert ("POST", "/api/") not in result
