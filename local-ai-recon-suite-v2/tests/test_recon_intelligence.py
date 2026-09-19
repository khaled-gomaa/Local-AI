import json

from ai.recon_insight import parse_result
from recon.traffic import TrafficStore

def _request(path='/dashboard?user_id=123&next=/orders', method='GET', body=''):
    return (
        f'{method} {path} HTTP/1.1\r\n'
        'Host: target.test\r\n'
        'Accept: text/html\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        '\r\n'
        + body
    )

def _response(body, status=200, extra_headers=''):
    return (
        f'HTTP/1.1 {status} OK\r\n'
        'Content-Type: text/html\r\n'
        + extra_headers
        + '\r\n'
        + body
    )

def test_traffic_graph_detects_relationships_and_candidates(tmp_path):
    store = TrafficStore(tmp_path / 'traffic.db')
    try:
        store.observe({
            'message_id': '1',
            'request': _request(),
            'response': _response(
                '<html><title>Dashboard</title>'
                '<a href="/orders?user_id=123">Orders</a>'
                '<a href="/profile">Profile</a></html>'
            ),
        })
        store.observe({
            'message_id': '2',
            'request': _request('/orders?user_id=123'),
            'response': _response(
                '<html><a href="/orders/1">Order</a></html>',
                extra_headers=(
                    'Access-Control-Allow-Origin: *\r\n'
                    'Access-Control-Allow-Credentials: true\r\n'
                ),
            ),
        })

        snapshot = store.snapshot('target.test')
        paths = {page['path'] for page in snapshot['pages']}
        assert '/dashboard' in paths
        assert '/orders' in paths

        relations = {r['relation'] for r in snapshot['relationships']}
        assert 'link' in relations
        assert any(r.startswith('shared_parameter:user_id') for r in relations)

        classes = {c['class'] for c in snapshot['candidates']}
        assert 'idor_candidate' in classes
        assert 'open-redirect_or_ssrf_candidate' in classes
        assert 'cors_candidate' in classes
    finally:
        store.close()

def test_insight_parser_normalizes_shape():
    result = parse_result(
        '```json\n'
        '{'
        '"summary": "The API exposes user resources.",'
        '"hypotheses": [{"class": "idor", "confidence": 0.5}],'
        '"gaps": []'
        '}'
        '\n```'
    )

    assert result['summary'].startswith('The API')
    assert len(result['hypotheses']) == 1
    assert isinstance(result['relationships'], list)
